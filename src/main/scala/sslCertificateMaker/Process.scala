package sslCertificateMaker

import scala.concurrent.blocking
import scala.concurrent.duration.DurationInt

import scala.collection.JavaConversions._
import java.security.KeyPair
import org.shredzone.acme4j.Order
import akka.actor.ActorSystem
import org.shredzone.acme4j.Authorization
import scala.concurrent.Future
import java.time.Instant
import org.shredzone.acme4j.Account
import scala.concurrent.Await
import scala.concurrent.duration.FiniteDuration
import scala.concurrent.Promise
import org.shredzone.acme4j.challenge.Http01Challenge
import org.shredzone.acme4j.exception.AcmeRetryAfterException
import java.time.Duration
import java.util.concurrent.TimeUnit
import scala.util.control.NonFatal
import org.shredzone.acme4j.util.CSRBuilder
import java.io.FileWriter
import org.shredzone.acme4j.Status
import scala.concurrent.ExecutionContext

object Process {
	private case class AuthResult(success: Boolean);
}

class Process(account: Account, domains: List[String], domainKeyPair: KeyPair, organization: String, oCertificateExpiration: Option[Instant], csrFileName: String) {
	import Process._

	private val system: ActorSystem = ActorSystem("ssl-certificate-maker");
	implicit val ec = system.dispatcher;
	
	def start(): Future[Unit] = {
		
		val orderBuilder = account.newOrder().domains(domains);

		oCertificateExpiration.map { instant =>
			orderBuilder.notAfter(instant)
		}

		val order: Order = orderBuilder.create();


		def loop(remainingAuths: List[Authorization], chain: Future[List[AuthResult]]): Future[List[AuthResult]] = {
			remainingAuths match {
				case Nil => chain
				case head :: tail =>
					loop(tail, chain.flatMap { list => processAuth(head).map(authResult => authResult :: list) })
			}
		}

		println("authorization process started")
		val completionOfAllProcesses =
			loop(order.getAuthorizations().toList, Future.successful(Nil))
				.map(_.reverse);

		for {
			authResults <- completionOfAllProcesses
		} {
			if (authResults.forall(_.success)) {
				println("All the challenges were accomplished. Creating the CSR ...");
				val csrb: CSRBuilder = new CSRBuilder();
				domains.foreach(domain => csrb.addDomain(domain));
				csrb.setOrganization(organization)
				csrb.sign(domainKeyPair);
				println(s"Saving CSR to file $csrFileName ...");
				csrb.write(new FileWriter(csrFileName));

				val csr = csrb.getEncoded();
				order.execute(csr);
				println("certificate creation order was executed. Waiting ...")
			}
		}

		// TODO download the certificate signed by the Let's Encrypt CA

		completionOfAllProcesses.map(_ => system.terminate());
		system.whenTerminated.map(_ => ())(scala.concurrent.ExecutionContext.Implicits.global)
	}
	
	private def processAuth(auth: Authorization): Future[AuthResult] = {
		println(s"Processing authorization ${auth.getJSON} ...");
		val challenge: Http01Challenge = auth.findChallenge(Http01Challenge.TYPE);

		val server = new Server(challenge.getToken, challenge.getAuthorization)(system);

		def waitAuth(auth: Authorization): Future[AuthResult] = {
			val promise = Promise[AuthResult]();

			def loop(duration: FiniteDuration): Unit = {
				print(".");
				implicit val ec = system.dispatcher;
				this.wait(duration).map { _ =>
					try {
						val status = blocking {
							auth.update(); // throws AcmeRetryAfterException
							auth.getStatus;
						}
						if (status == Status.INVALID) {
							promise.success(AuthResult(false))
						} else if (status == Status.VALID) {
							promise.success(AuthResult(true))
						} else
							loop(5.seconds)
					} catch {
						case arae: AcmeRetryAfterException => // thrown by auth.update()
							val x = Duration.between(arae.getRetryAfter, Instant.now());
							print(s"[${x.getSeconds}]")
							loop(FiniteDuration(x.getSeconds, TimeUnit.SECONDS))

						case NonFatal(e) =>
							promise.failure(e);
					}
				}

			}
			print("Waiting authorization:");
			loop(5.seconds);
			promise.future;
		}

		implicit val ec = system.dispatcher;
		for {
			_ <- server.ready.future
			_ = challenge.trigger();
			_ <- server.challengeWasStarted.future
			authResult <- waitAuth(auth)
			_ <- server.terminate()
		} yield authResult
	}

	private def wait(duration: FiniteDuration): Future[Unit] = {
		val promise = Promise[Unit]();
		system.scheduler.scheduleOnce(duration) { promise.success(()) }
		promise.future;
	}	
}