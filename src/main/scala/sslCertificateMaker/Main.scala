package sslCertificateMaker

import scala.concurrent.duration.DurationInt
import scala.concurrent.blocking
import java.io.FileReader
import java.io.FileWriter
import java.net.URI
import java.net.URL
import scala.collection.breakOut
import scala.collection.JavaConversions._
import org.shredzone.acme4j.Account
import org.shredzone.acme4j.AccountBuilder
import org.shredzone.acme4j.Metadata
import org.shredzone.acme4j.Session
import org.shredzone.acme4j.util.KeyPairUtils
import org.shredzone.acme4j.exception.AcmeServerException
import org.shredzone.acme4j.Login
import org.shredzone.acme4j.Order
import java.time.Instant
import java.time.Duration
import org.shredzone.acme4j.Status
import org.shredzone.acme4j.Authorization
import org.shredzone.acme4j.challenge.Http01Challenge
import scala.concurrent.Future
import scala.concurrent.Promise
import scala.annotation.tailrec
import scala.concurrent.duration.FiniteDuration
import org.shredzone.acme4j.exception.AcmeRetryAfterException
import java.util.concurrent.TimeUnit
import scala.util.control.NonFatal
import org.shredzone.acme4j.util.CSRBuilder

/** Para hacer esto fui guiado por "https://shredzone.org/maven/acme4j/" cuyo repositorio git esta en: "https://github.com/shred/acme4j" */
object Main {
	import scala.concurrent.ExecutionContext.Implicits.global;

	private case class AuthResult(success: Boolean);

	private final val PARAM_env = "env";
	private final val PARAM_acmeAccountKeyPairFileName = "acmeAccountKeyPairFileName";
	private final val PARAM_acmeAccountKeyPairCmd = "acmeAccountKeyPairCmd";
	private final val PARAM_domainKeyPairFileName = "domainKeyPairFileName";
	private final val PARAM_domainKeyPairCmd = "domainKeyPairCmd";
	private final val PARAM_organization = "organization";
	private final val PARAM_accountLocationUrl = "accountLocationUrl";
	private final val PARAM_allowNewAcmeAccountCreation = "createAcmeAccount";
	private final val PARAM_orderCertificateFor = "orderCertificateFor";
	private final val PARAM_certificateExpirationInDays = "certificateExpirationInDays";
	private final val PARAM_csrFileName = "csrFileName";

	private final val paramNames = Map(
		PARAM_env -> "Required: Specifies which environment to use. Valid values are: `staging` and `production`.",
		PARAM_acmeAccountKeyPairFileName -> "Required: specifies the file name from/to where the ACME account key pair would be saved/loaded.",
		PARAM_acmeAccountKeyPairCmd -> s"Required: valid values are: `create` to create ans save a new key pair; and `load` to load it from a file. Both options require the parameter `$PARAM_acmeAccountKeyPairFileName` be defined.",
		PARAM_accountLocationUrl -> "If specified the ACME account is obtained from the indicated URL.",
		PARAM_allowNewAcmeAccountCreation -> "Optional. This parameter is considered only if the ACME account key pair is not asociated with an ACME account. If specified with value `yes` allows the creation of a new ACME account",
		PARAM_domainKeyPairFileName -> s"Required when the parameter `$PARAM_orderCertificateFor is specified. Specifies from/to which file the domain key pair should be loaded/saved depending on the `$PARAM_domainKeyPairCmd`.",
		PARAM_domainKeyPairCmd -> s"Required when the parameter `$PARAM_orderCertificateFor` is specified. Specifies how to obtain the domain key pair: `load` it, or `create` and save it.",
		PARAM_organization -> s"Required when the parameter `$PARAM_orderCertificateFor` is specified. Specifies the organization to which the certificate would be issued",
		PARAM_orderCertificateFor -> "instructs the creation of a certificate for the comma separated list of domains",
		PARAM_certificateExpirationInDays -> s"Required when the parameter `$PARAM_orderCertificateFor` is specified. Specifies the days of live of the certificate before expiration",
		PARAM_csrFileName -> "name of the file where the certificate signing request would be saved"
	);

	def main(args: Array[String]): Unit = {
		val params: Map[String, String] = {
			(for { arg <- args } yield {
				val split = arg.split('=');
				if (split.size != 2)
					throw new AssertionError("Error de sintaxix en parámetro: `$arg`")
				else if (paramNames.contains(split(0)))
					split(0) -> split(1)
				else
					throw new AssertionError(s"El parámetro `${split(0)}` no existe.")
			})(breakOut)
		};
		
		if( params.isEmpty) {
			println(s"PARAMETERS:\n${paramNames.map(p => s"${p._1}: ${p._2}").mkString("\n")}");
			return;
		}

		val letsEncriptUri = params.get(PARAM_env) match {
			case Some("staging") => "acme://letsencrypt.org/staging";
			case Some("production") => "acme://letsencrypt.org";
			case _ => throw new AssertionError(s"El parámetro `$PARAM_env` es obligatorio y la sintaxis es: `$PARAM_env=staging` o `$PARAM_env=production`.")
		}
		val session: Session = new Session(letsEncriptUri);

		val meta: Metadata = session.getMetadata();
		val tos: URI = meta.getTermsOfService();
		val website: URL = meta.getWebsite();
		println(s"terms of service: $tos");
		println(s"let's encript website: $website");

		val acmeAccountKeyPairFileName =
			params.get(PARAM_acmeAccountKeyPairFileName) match {
				case Some(fn) => fn
				case None => throw new AssertionError(s"El parámetro `$PARAM_acmeAccountKeyPairFileName` es obligatorio y tiene dos valores posibles: `true` o `false`.");
			}

		val acmeAccountKeyPair = params.get(PARAM_acmeAccountKeyPairCmd) match {
			case Some("create") =>
				println(s"creating a new ACME account key pair");
				val keyPair = KeyPairUtils.createKeyPair(2048);
				println(s"saving new ACME account key pair to $acmeAccountKeyPairFileName");
				val fileWriter: FileWriter = new FileWriter(acmeAccountKeyPairFileName)
				try {
					KeyPairUtils.writeKeyPair(keyPair, fileWriter);
					keyPair
				} finally fileWriter.close();

			case Some("load") =>
				println(s"loading ACME account key pair from $acmeAccountKeyPairFileName");
				val fileReader: FileReader = new FileReader(acmeAccountKeyPairFileName);
				try {
					KeyPairUtils.readKeyPair(fileReader);
				} finally fileReader.close()

			case _ =>
				throw new AssertionError(s"El parámetro `$PARAM_acmeAccountKeyPairCmd` tiene dos valores posibles: `create` y `load`");
		}

		val oDomainKeyPairFileName = params.get(PARAM_domainKeyPairFileName);
		val oDomainKeyPair = params.get(PARAM_domainKeyPairCmd).map { source =>
			oDomainKeyPairFileName match {
				case Some(domainKeyPairFileName) =>
					source match {
						case "create" =>
							println(s"creating a new domain key pair");
							val keyPair = KeyPairUtils.createKeyPair(2048);
							val fileWriter: FileWriter = new FileWriter(domainKeyPairFileName)
							try {
								println(s"saving new domain key pair to $domainKeyPairFileName");
								KeyPairUtils.writeKeyPair(keyPair, fileWriter);
								keyPair
							} finally fileWriter.close();

						case "load" =>
							println(s"loading domain key pair from $domainKeyPairFileName");
							val fileReader: FileReader = new FileReader(acmeAccountKeyPairFileName);
							try {
								KeyPairUtils.readKeyPair(fileReader);
							} finally fileReader.close()

						case _ =>
							throw new AssertionError(s"El parámetro `$PARAM_domainKeyPairCmd` tiene dos valores posibles: `create` y `load`");
					}

				case None =>
					throw new AssertionError(s"El parámetro `$PARAM_domainKeyPairCmd` requiere del parámetro `$PARAM_domainKeyPairFileName`.")
			}
		}

		val oOrganization = params.get(PARAM_organization)

		val account: Account =
			params.get(PARAM_accountLocationUrl) match {
				case Some(accountLocationUrl) =>
					println(s"Obtaing the ACME account from $accountLocationUrl");
					val login: Login = session.login(new URL(accountLocationUrl), acmeAccountKeyPair);
					login.getAccount();

				case None =>
					try {
						println("trying to obtain the ACME account from the key pair ...");
						new AccountBuilder().onlyExisting().useKeyPair(acmeAccountKeyPair).create(session);
					} catch {
						case ase: AcmeServerException if ase.getMessage == "No account exists with the provided key" =>
							print(" the supplied ACME account key pair is not associated with an ACME account.");

							params.get(PARAM_allowNewAcmeAccountCreation) match {
								case Some("yes") =>
									println("creating a new ACME account ...");
									new AccountBuilder()
										.agreeToTermsOfService()
										.useKeyPair(acmeAccountKeyPair)
										.create(session);

								case _ =>
									throw new AssertionError(s"If the ACME account key pair is not associated with an ACME account, the parámeter `$PARAM_allowNewAcmeAccountCreation`'s value should be `yes` in order to allow the creation of a new ACME account.")
							}
					}
			}

		val accountLocationUrl: URL = account.getLocation();
		println(s"Account location URL: $accountLocationUrl");

		val oCsrFileName: Option[String] = params.get(PARAM_csrFileName);

		params.get(PARAM_orderCertificateFor).foreach { domainsString =>
			(oDomainKeyPair, oOrganization, oCsrFileName) match {
				case (Some(domainKeyPair), Some(organization), Some(csrFileName)) =>
					val domains = domainsString.split(',').toList;
					println(s"creating certification creation order for domains $domains signed with the domain key ${oDomainKeyPairFileName.get}")
					val orderBuilder = account.newOrder().domains(domains);

					params.get(PARAM_certificateExpirationInDays).foreach { durationString =>
						val duration = java.lang.Long.parseUnsignedLong(durationString)
						orderBuilder.notAfter(Instant.now().plus(Duration.ofDays(duration)))
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

				case _ =>
					throw new AssertionError(s"El parámetro `$PARAM_orderCertificateFor` requiere que los parámetros `$PARAM_domainKeyPairCmd`, `$PARAM_organization`, y `$PARAM_csrFileName` estén definidos.");

			}

		}
	}

	private def processAuth(auth: Authorization): Future[AuthResult] = {
		println(s"Processing authorization ${auth.getJSON} ...");
		val challenge: Http01Challenge = auth.findChallenge(Http01Challenge.TYPE);

		val server = new Server(challenge.getToken, challenge.getAuthorization);

		def waitAuth(auth: Authorization): Future[AuthResult] = {
			val promise = Promise[AuthResult]();

			def loop(duration: FiniteDuration): Unit = {
				print(".");
				server.wait(duration).map { _ =>
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

		for {
			_ <- server.ready.future
			_ = challenge.trigger();
			_ <- server.challengeWasStarted.future
			authResult <- waitAuth(auth)
			_ <- server.terminate()
		} yield authResult
	}

}