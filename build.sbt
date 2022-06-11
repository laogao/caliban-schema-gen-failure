ThisBuild / scalaVersion := "3.1.2"

lazy val root = (project in file("."))
  .settings(
    libraryDependencies ++= Seq(
      "dev.zio" %% "zio" % "1.0.15",
      "com.github.ghostdogpr" %% "caliban" % "1.4.1",
      "com.github.ghostdogpr" %% "caliban-zio-http" % "1.4.1",
      "org.postgresql" % "postgresql" % "42.3.6",
      "org.flywaydb" % "flyway-core" % "8.5.11",
      "io.getquill" %% "quill-jdbc-zio" % "3.18.0"
        exclude ("org.scala-lang.modules", "scala-collection-compat_2.13")
        exclude ("com.lihaoyi", "sourcecode_2.13")
        exclude ("com.lihaoyi", "fansi_2.13")
        exclude ("com.lihaoyi", "pprint_2.13"),
      "com.typesafe" % "config" % "1.4.2"
    )
  )
