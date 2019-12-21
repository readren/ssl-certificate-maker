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
import org.shredzone.acme4j.Certificate
import scala.util.Success
import scala.util.Failure

object Process {
	private case class AuthResult(success: Boolean);

	class AppException(msj: String) extends Exception(msj)
}

class Process(account: Account, domains: List[String], domainKeyPair: KeyPair, organization: String, oCertificateExpiration: Option[Instant], csrFileName: String, signedCertFileName: String) {
	import Process._

	private val system: ActorSystem = ActorSystem("ssl-certificate-maker");
	implicit val ec = system.dispatcher;

	def start(): Future[Unit] = {
		println(s"Starting the certification process for domains $domains.");

		val orderBuilder = account.newOrder().domains(domains);

		oCertificateExpiration.map { instant =>
			orderBuilder.notAfter(instant)
		}

		val order: Order = orderBuilder.create();
		val authorizations = order.getAuthorizations().toList;
		if (!authorizations.forall { auth =>
			val status = auth.getStatus;
			status == Status.PENDING || status == Status.PROCESSING || status == Status.VALID
		}) {
			return Future.successful(s"Certification process was not started because at least one of the authorizations is in an irreversible state.\nAuthorizations states: ${authorizations.map(a => a.getIdentifier -> a.getStatus)}")
		}

		val authorizationsIHaveToChallenge = authorizations.filter { auth =>
			val status = auth.getStatus;
			status == Status.PENDING || status == Status.PROCESSING || status == Status.READY // TODO investigar cuales estados indican necesidad de challenge
		}

		def loop(remainingAuths: List[Authorization], chain: Future[Boolean]): Future[Unit] = {
			def buildError() = new AppException(s"The certification process was canceled because at least one of the authorizations changed to an invalid state.\nAuthorizations states: ${authorizations.map(a => a.getIdentifier -> a.getStatus)}\nProblem: ${order.getError}"); 
			
			remainingAuths match {
				case Nil => chain.map { previousAuthWasSuccessful => 
					if(previousAuthWasSuccessful) ()
					else Future.failed(buildError())
				}
				case head :: tail =>
					chain.flatMap { previousAuthWasSuccessful =>
						if (previousAuthWasSuccessful)
							loop(tail, processAuth(head));
						else
							Future.failed(buildError());
					}
			}
		}

		println(s"Authorization process started. There are ${authorizationsIHaveToChallenge.size} challenge to acomplish.")
		val completionOfAllAuthProcesses = loop(authorizationsIHaveToChallenge, Future.successful(true));

		val completionOfCertificationProcess =
			for {
				_ <- completionOfAllAuthProcesses
				_ = println("All the challenges were accomplished.")
				signedCertificate <- buildCsrAndWaitForItsAproval(order)
			} yield {
				println(s"""Saving the signed certificate to file "$signedCertFileName".""");
				val fileWriter: FileWriter = new FileWriter(signedCertFileName)
				try {
					signedCertificate.writeCertificate(fileWriter)
				} finally fileWriter.close();

			}

		completionOfCertificationProcess.onComplete {
			case Success(_) =>
				system.terminate()
			case Failure(e) =>
				print("The certification process was canceled with this error message: " + e.getMessage)
				system.terminate()
		}
		system.whenTerminated.map(_ => ())(scala.concurrent.ExecutionContext.Implicits.global)
	}

	private def buildCsrAndWaitForItsAproval(order: Order): Future[Certificate] = {
		println("Creating the CSR ...");
		val csrb: CSRBuilder = new CSRBuilder();
		domains.foreach(domain => csrb.addDomain(domain));
		csrb.setOrganization(organization)
		csrb.sign(domainKeyPair);

		println(s"""Saving CSR to file "$csrFileName" ...""");
		blocking { csrb.write(new FileWriter(csrFileName)) };

		val csr = csrb.getEncoded();
		order.execute(csr);
		println("The CSR (certificate signing request) was sent to Let's Encript. Waiting for the signed certificate ...");
		waitCsrApproval(order).transform {
			case Success(Some(certificate)) => Success(certificate)
			case Success(None) => Failure(new AppException("The order changed to an invalid state."));
			case Failure(e) => Failure(e)
		}

	}

	private def processAuth(auth: Authorization): Future[Boolean] = {
		println(s"Processing authorization ${auth.getJSON} ...");
		val challenge: Http01Challenge = auth.findChallenge(Http01Challenge.TYPE);

		val server = new Server(challenge.getToken, challenge.getAuthorization)(system);

		implicit val ec = system.dispatcher;
		for {
			_ <- server.ready.future
			_ = println("The fake server is ready to catch the challenge.")
			_ = challenge.trigger();
			_ = println("The challenge has been triggered.")
			_ <- server.challengeWasCatched.future
			_ = println("The fake sever has catched the challenge.")
			authResult <- waitAuth(auth)
			_ = println(if(authResult) "The challenge was accomplished." else "The authorization changed to an invalid state.")
			_ = println("Terminating the fake server...")
			_ <- server.terminate()
		} yield {
			println("The fake sever has been terminated.")
			authResult
		}
	}

	private def waitAuth(auth: Authorization): Future[Boolean] = {
		print("\nWaiting authorization");
		pollCompletion(5.seconds) { () =>
			val status = blocking {
				auth.update(); // throws AcmeRetryAfterException
				auth.getStatus;
			}
			if (status == Status.INVALID) {
				Some(false)
			} else if (status == Status.VALID) {
				Some(true)
			} else
				None
		}
	}

	private def waitCsrApproval(order: Order): Future[Option[Certificate]] = {
		pollCompletion(5.seconds) { () =>
			val status = blocking {
				order.update(); // throws AcmeRetryAfterException
				order.getStatus;
			}
			if (status == Status.INVALID) {
				Some(None)
			} else if (status == Status.VALID) {
				Some(Some(order.getCertificate))
			} else
				None
		}
	}

	private def pollCompletion[Result](initialPollInterval: FiniteDuration)(completionTest: () => Option[Result]): Future[Result] = {
		val promise = Promise[Result]();

		def loop(duration: FiniteDuration, tryNumber: Int): Unit = {
			print(".")
			implicit val ec = system.dispatcher;
			this.wait(duration).map { _ =>
				try {
					completionTest() match {
						case Some(result) =>
							println();
							promise.success(result)
						case None =>
							loop(initialPollInterval + 1.second * tryNumber, tryNumber + 1)
					}
				} catch {
					case arae: AcmeRetryAfterException => // thrown by auth.update()
						val x = Duration.between(arae.getRetryAfter, Instant.now());
						print(s"[${x.getSeconds}]")
						loop(FiniteDuration(x.getSeconds, TimeUnit.SECONDS), 0)

					case NonFatal(e) =>
						promise.failure(e);
				}
			}

		}
		loop(initialPollInterval, 0);
		promise.future;
	}

	private def wait(duration: FiniteDuration): Future[Unit] = {
		val promise = Promise[Unit]();
		system.scheduler.scheduleOnce(duration) { promise.success(()) }
		promise.future;
	}
}