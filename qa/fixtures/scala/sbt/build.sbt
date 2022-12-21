import Dependencies._

lazy val root = (project in file(".")).
  settings(
    inThisBuild(List(
      organization := "com.example",
      scalaVersion := "2.12.15",
      version      := "0.1.0-SNAPSHOT"
    )),
    name := "Hello",
    libraryDependencies += scalaTest % Test,
    libraryDependencies += "com.fasterxml.jackson.core" % "jackson-databind" % "2.9.2" % "compile",
    libraryDependencies += "org.mozilla" % "rhino" % "1.7.10" % "compile",
    libraryDependencies += "org.apache.geode" % "geode-core" % "1.1.1" % "compile"
  )
