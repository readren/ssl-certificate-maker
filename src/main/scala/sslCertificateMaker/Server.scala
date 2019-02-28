package sslCertificateMaker

import scala.concurrent.ExecutionContext
import scala.concurrent.Future
import scala.concurrent.Promise
import scala.concurrent.duration.DurationInt
import scala.util.Failure
import scala.util.Success

import akka.actor.ActorSystem
import akka.event.Logging
import akka.http.scaladsl.Http
import akka.http.scaladsl.server.Directives._enhanceRouteWithConcatenation // sin esto no anda el PathMatcher en eclipse
import akka.http.scaladsl.server.Directives._segmentStringToPathMatcher // sin esto no anda el PathMatcher en eclipse
import akka.http.scaladsl.server.Directives.complete
import akka.http.scaladsl.server.Directives.extractUnmatchedPath
import akka.http.scaladsl.server.Directives.logRequestResult
import akka.http.scaladsl.server.Directives.pathPrefix
import akka.http.scaladsl.server.Route
import akka.stream.ActorMaterializer

class Server(token: String, content: String)(implicit system: ActorSystem) {
	println("starting the server ...");
	private implicit val materializer: ActorMaterializer = ActorMaterializer()
	private implicit val executionContext: ExecutionContext = system.dispatcher;

	private val http = Http()

	val ready: Promise[Unit] = Promise();
	val challengeWasCatched: Promise[Unit] = Promise();

	private lazy val routes: Route =
		logRequestResult(("server activity:", Logging.InfoLevel)) {
			pathPrefix(".well-known" / "acme-challenge" / token) {
				this.challengeWasCatched.trySuccess(())
				complete(content);
			} ~ extractUnmatchedPath { path =>
				complete(path.toString)
			}
		}

	//#http-server
	private val serverBinding: Future[Http.ServerBinding] = this.http.bindAndHandle(routes, "0.0.0.0", 80)

	serverBinding.onComplete {
		case Success(bound) =>
			ready.success(());
			println(s"Server online at http://${bound.localAddress.getHostString}:${bound.localAddress.getPort}/");

		case Failure(e) =>
			ready.failure(e)
			challengeWasCatched.failure(e);
			Console.err.println(s"Server could not start!")
			e.printStackTrace()
	}

	def terminate(): Future[Unit] = {
		for {
			normalBinding <- this.serverBinding
			normalTerminated <- normalBinding.terminate(3.seconds)
			_ <- this.http.shutdownAllConnectionPools()
		} yield ()
	}
}