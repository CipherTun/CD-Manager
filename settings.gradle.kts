pluginManagement { repositories { google(); mavenCentral(); gradlePluginPortal() } }
dependencyResolutionManagement { repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS); repositories { google(); mavenCentral() } }
rootProject.name = "CD Manager"
include(":app", ":backend-kotlin", ":backend-java", ":backend-archive", ":backend-msgpack", ":backend-android", ":backend-format", ":backend-protocol")
