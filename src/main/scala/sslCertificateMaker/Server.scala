package sslCertificateMaker

import scala.concurrent.duration.DurationInt
import scala.concurrent.ExecutionContext
import scala.concurrent.Await
import scala.concurrent.duration.Duration
import scala.concurrent.Future
import scala.util.Failure
import scala.util.Success
import akka.http.scaladsl.server.Directives._
import akka.stream.ActorMaterializer
import akka.actor.ActorSystem
import akka.http.scaladsl.Http
import akka.http.scaladsl.server.Route
import akka.actor.ActorRef
import scala.concurrent.Promise
import scala.concurrent.duration.FiniteDuration
import akka.event.Logging

class Server(token: String, content: String)(implicit system: ActorSystem) {
	println("starting the server ...");
	private implicit val materializer: ActorMaterializer = ActorMaterializer()
	private implicit val executionContext: ExecutionContext = system.dispatcher;

	private val http = Http()

	val ready: Promise[Unit] = Promise();
	val challengeWasStarted: Promise[Unit] = Promise();

	private lazy val routes: Route =
		logRequestResult(("server activity:", Logging.InfoLevel)) {
			path(s".well-known/acme-challenge/$token") {
				println("challenge was catched")
				this.challengeWasStarted.success(())
				complete(content);
			}
		}

	//#http-server
	private val serverBinding: Future[Http.ServerBinding] = this.http.bindAndHandle(routes, "localhost", 80)

	serverBinding.onComplete {
		case Success(bound) =>
			ready.success(());
			println(s"Server online at http://${bound.localAddress.getHostString}:${bound.localAddress.getPort}/");

		case Failure(e) =>
			ready.failure(e)
			challengeWasStarted.failure(e);
			Console.err.println(s"Server could not start!")
			e.printStackTrace()
	}

	def terminate(): Future[Unit] = {
		println("terminating the server ...")
		for {
			normalBinding <- this.serverBinding
			normalTerminated <- normalBinding.terminate(3.seconds)
			_ <- this.http.shutdownAllConnectionPools()
		} yield {
			println("server terminated.")
			()
		}
	}
}