package sslCertificateMaker

import java.io.FileReader
import java.io.FileWriter
import java.net.URI
import java.net.URL
import java.time.Duration
import java.time.Instant

import scala.collection.breakOut
import scala.concurrent.Await
import scala.concurrent.duration.{ Duration=>ScDuration }

import org.shredzone.acme4j.Account
import org.shredzone.acme4j.AccountBuilder
import org.shredzone.acme4j.Login
import org.shredzone.acme4j.Metadata
import org.shredzone.acme4j.Session
import org.shredzone.acme4j.exception.AcmeServerException
import org.shredzone.acme4j.util.KeyPairUtils

/** Para hacer esto fui guiado por "https://shredzone.org/maven/acme4j/" cuyo repositorio git esta en: "https://github.com/shred/acme4j" */
object Main {

	private final val PARAM_env = "env";
	private final val PARAM_acmeAccountKeyPairFileName = "acmeAccountKeyPairFileName";
	private final val PARAM_acmeAccountKeyPairCmd = "acmeAccountKeyPairCmd";
	private final val PARAM_domainKeyPairFileName = "domainKeyPairFileName";
	private final val PARAM_domainKeyPairCmd = "domainKeyPairCmd";
	private final val PARAM_organization = "organization";
	private final val PARAM_accountLocationUrl = "accountLocationUrl";
	private final val PARAM_allowNewAcmeAccountCreation = "allowNewAcmeAccountCreation";
	private final val PARAM_orderCertificateFor = "orderCertificateFor";
	private final val PARAM_certificateExpirationInDays = "certificateExpirationInDays";
	private final val PARAM_csrFileName = "csrFileName";
	private final val PARAM_signedCertFileName = "signedCertFileName";

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
		PARAM_csrFileName -> "name of the file where the certificate signing request would be saved",
		PARAM_signedCertFileName -> "name of the fine where the signed certificate would be saved"
	);

	def main(args: Array[String]): Unit = {
		val params: Map[String, String] = {
			(for { arg <- args } yield {
				val split = arg.split('=');
				if (split.length != 2)
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

		val meta: Metadata = session.getMetadata;
		val tos: URI = meta.getTermsOfService;
		val website: URL = meta.getWebsite;
		println(s"terms of service: $tos");
		println(s"let's encript website: $website");

		val acmeAccountKeyPairFileName =
			params.get(PARAM_acmeAccountKeyPairFileName) match {
				case Some(fn) => fn
				case None => throw new AssertionError(s"El parámetro `$PARAM_acmeAccountKeyPairFileName` es obligatorio y tiene dos valores posibles: `true` o `false`.");
			}

		val acmeAccountKeyPair = params.get(PARAM_acmeAccountKeyPairCmd) match {
			case Some("create") =>
				println(s"Creating a new ACME account key pair");
				val keyPair = KeyPairUtils.createKeyPair(2048);
				println(s"""Saving new ACME account key pair to "$acmeAccountKeyPairFileName".""");
				val fileWriter: FileWriter = new FileWriter(acmeAccountKeyPairFileName)
				try {
					KeyPairUtils.writeKeyPair(keyPair, fileWriter);
					keyPair
				} finally fileWriter.close();

			case Some("load") =>
				println(s"""Loading ACME account key pair from "$acmeAccountKeyPairFileName".""");
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
							println(s"Creating a new domain key pair");
							val keyPair = KeyPairUtils.createKeyPair(2048);
							println(s"""Saving new domain key pair to "$domainKeyPairFileName".""");
							val fileWriter: FileWriter = new FileWriter(domainKeyPairFileName)
							try {
								KeyPairUtils.writeKeyPair(keyPair, fileWriter);
								keyPair
							} finally fileWriter.close();

						case "load" =>
							println(s"""Loading domain key pair from "$domainKeyPairFileName".""");
							val fileReader: FileReader = new FileReader(domainKeyPairFileName);
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
				case Some(accountLocationUrlValue) =>
					println(s"Obtaining the ACME account from $accountLocationUrlValue");
					val login: Login = session.login(new URL(accountLocationUrlValue), acmeAccountKeyPair);
					login.getAccount;

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

		val accountLocationUrl: URL = account.getLocation;
		println(s"Account location URL: $accountLocationUrl");

		val oCsrFileName: Option[String] = params.get(PARAM_csrFileName);
		val oSignedCertFileName: Option[String] = params.get(PARAM_signedCertFileName);

		params.get(PARAM_orderCertificateFor).foreach { domainsString =>
			(oDomainKeyPair, oOrganization, oCsrFileName, oSignedCertFileName) match {
				case (Some(domainKeyPair), Some(organization), Some(csrFileName), Some(signedCertFileName)) =>
					val domains = domainsString.split(',').toList;

					val oCertificateExpiration = params.get(PARAM_certificateExpirationInDays).map { durationString =>
						val duration = java.lang.Long.parseUnsignedLong(durationString)
						Instant.now().plus(Duration.ofDays(duration))
					}
					
					val process = new Process(account, domains, domainKeyPair, organization, oCertificateExpiration, csrFileName, signedCertFileName);
					Await.ready(process.start(), ScDuration.Inf)

				case _ =>
					throw new AssertionError(s"El parámetro `$PARAM_orderCertificateFor` requiere que los parámetros `$PARAM_domainKeyPairCmd`, `$PARAM_organization`, `$PARAM_csrFileName`, y `$PARAM_signedCertFileName` estén definidos.");

			}
		}
	}

	
}