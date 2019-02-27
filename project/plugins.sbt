// This plugin adds commands to generate IDE project files
addSbtPlugin("com.typesafe.sbteclipse" % "sbteclipse-plugin" % "5.2.4")

// adds the task `dependencyUpdates` which shows a list of project dependencies that can be updated
addSbtPlugin("com.timushev.sbt" % "sbt-updates" % "0.3.4")

// adds several tasks that show the dependency tree. One of them is `dependencyBrowseGraph`, which opens a browser window with a visualization of the dependency graph
addSbtPlugin("net.virtual-void" % "sbt-dependency-graph" % "0.9.2")

// adds the tasks `re-start`, `re-stop`, and  `re-status` 
addSbtPlugin("io.spray" % "sbt-revolver" % "0.9.1")

// generates Scala source from the build definitions.
// addSbtPlugin("com.eed3si9n" % "sbt-buildinfo" % "0.6.1")

//addSbtPlugin("com.typesafe.sbt" % "sbt-native-packager" % "1.3.4")

