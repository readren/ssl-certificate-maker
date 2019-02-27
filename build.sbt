lazy val akkaHttpVersion = "10.1.7"
lazy val akkaVersion    = "2.5.21"

ThisBuild / scalaVersion := "2.12.8"
ThisBuild / version := "0.1.0"

lazy val root = (project in file("."))
	.settings(
		name := "ssl-certificate-maker",
	)

ThisBuild / libraryDependencies ++= Seq(
	"org.shredzone.acme4j" % "acme4j-client" % "2.6",
	"org.shredzone.acme4j" % "acme4j-utils" % "2.6",

	"com.typesafe.akka" %% "akka-actor"           % akkaVersion,
	"com.typesafe.akka" %% "akka-http"            % akkaHttpVersion,
	"com.typesafe.akka" %% "akka-http-spray-json" % akkaHttpVersion,
	"com.typesafe.akka" %% "akka-http-xml"        % akkaHttpVersion,
	"com.typesafe.akka" %% "akka-stream"          % akkaVersion
)
