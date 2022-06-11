import caliban.GraphQL.graphQL
import caliban.RootResolver
import caliban.schema.Annotations.GQLDeprecated
import caliban.schema.Annotations.GQLDescription
import caliban.schema.Schema
import zio.App
import zio.Has
import zio.RIO
import zio.Schedule
import zio.Task
import zio.UIO
import zio.ULayer
import zio.ZIO
import zio.ZLayer
import zio.blocking.Blocking
import zio.clock.Clock
import zio.console._
import zio.stream.ZStream
import java.util.Properties
import javax.sql.DataSource
import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import com.typesafe.config.ConfigFactory
import org.flywaydb.core.Flyway

object GraphQLServer extends zio.App:

  trait DataSourceProvider {
    def getDataSource: DataSource
  }

  import com.typesafe.config.Config
  import java.util.Properties

  def propsFromConfigWithPrefix(source: Config, prefix: String): Properties = {
    import scala.jdk.CollectionConverters.*
    val props = new Properties()
    source.entrySet.asScala
      .filter(_.getKey.startsWith(s"$prefix."))
      .foreach(entry =>
        props.put(
          entry.getKey.substring(prefix.length + 1),
          entry.getValue.unwrapped
        )
      )
    props
  }

  object DataSourceProvider {
    val fallback = new DataSourceProvider {
      lazy val ds = {
        println("creating datasource...")
        val source = ConfigFactory.load
        val config = new HikariConfig(
          propsFromConfigWithPrefix(source, "quill")
        )
        new HikariDataSource(config).asInstanceOf[DataSource]
      }
      def getDataSource = ds
    }
  }

  // Common wrappers
  case class Outcome(success: Boolean, code: Int, message: String)
  case class Response[T](outcome: Outcome, content: Option[T])
  case class Paged[T](count: Int, offset: Int, rows: List[T])

  case class LoginUser(
      id: Int,
      createdAt: Long,
      userType: Int,
      username: String,
      surname: String,
      firstName: String,
      active: Boolean,
      passHash: Option[String],
      remarks: Option[String],
      mobile: Option[String]
  )
  case class UserToken(
      username: String,
      token: String
  )
  case class UserVcode(
      username: String,
      vcode: String
  )
  case class User(
      id: Int,
      userType: Int,
      username: String,
      surname: String,
      firstName: String,
      mobile: Option[String],
      active: Boolean,
      remarks: Option[String],
      createdAt: Long
  )
  case class UserWithToken(user: User, token: String)
  case class ProjectMembership(projectName: String, role: String)
  case class UserWithProjects(user: User, projects: List[ProjectMembership])
  case class UserWithVcode(user: User, vcode: String, expiresAt: Long)
  case class LoginArgs(username: String, password: String)
  case class VcodeArgs(username: String)
  case class ChangePasswordByVcodeArgs(
      username: String,
      newPassword: String,
      vcode: String
  )
  case class RegisterArgs(
      username: String,
      mobile: String,
      surname: String,
      firstName: String,
      password: String,
      vcode: String
  )
  case class ChangePasswordArgs(
      token: String,
      username: String,
      password: String,
      newPassword: String
  )
  case class UpdateCurrentUserArgs(
      token: String,
      username: String,
      surname: String,
      firstName: String,
      remarks: Option[String],
      mobile: Option[String]
  )
  case class GetCurrentUserArgs(token: String)
  case class LogoutArgs(token: String)

  case class AdminGetUsersArgs(
      token: String,
      usernameStartsWith: String,
      offset: Int,
      limit: Int
  )
  case class AdminChangePasswordArgs(
      token: String,
      username: String,
      newPassword: String
  )
  case class AdminVcodeArgs(token: String, username: String)
  case class AdminCreateUserArgs(
      token: String,
      username: String,
      surname: String,
      firstName: String,
      active: Boolean,
      remarks: Option[String],
      mobile: Option[String]
  )
  case class AdminUpdateUserArgs(
      token: String,
      username: String,
      surname: String,
      firstName: String,
      active: Boolean,
      remarks: Option[String],
      mobile: Option[String]
  )

  case class Authority(
      id: Int,
      createdAt: Long,
      creatorId: Int,
      authorityCode: String,
      authorityName: String,
      remarks: Option[String]
  )
  case class Bill(
      id: Int,
      createdAt: Long,
      creatorId: Int,
      authorityId: Int,
      authorityCode: String,
      billCode: String,
      billText: String,
      quota: Int,
      expiresOn: String,
      expiresAt: Long,
      remarks: Option[String]
  )
  case class Project(
      id: Int,
      createdAt: Long,
      creatorId: Int,
      authorityId: Int,
      billId: Int,
      ownerId: Int,
      projectType: Int,
      projectName: String,
      projectStatus: Int,
      pi: Option[String],
      remarks: Option[String],
      supportedPermits: Int
  )
  case class Organization(
      id: Int,
      createdAt: Long,
      creatorId: Int,
      projectId: Int,
      orgLevel: Int,
      orgName: String,
      parentId: Option[Int]
  )
  case class Permit(
      permitKey: Int,
      permitName: String
  )
  case class ProjectRole(
      id: Int,
      createdAt: Long,
      creatorId: Int,
      roleName: String,
      permits: Int
  )
  case class ProjectMember(
      id: Int,
      createdAt: Long,
      creatorId: Int,
      projectId: Int,
      userId: Int,
      roleName: String,
      permits: Int,
      active: Boolean,
      deleted: Boolean,
      displayName: Option[String],
      l1OrgId: Option[Int],
      l2OrgId: Option[Int],
      l3OrgId: Option[Int],
      remarks: Option[String],
      joinedAt: Option[Long]
  )

  case class ValidateBillArgs(token: String, billText: String)
  case class BillContent(
      authorityCode: String,
      billCode: String,
      authorityName: String,
      quota: Int,
      expiresOn: String
  )
  case class BillValidation(
      validated: Boolean,
      billContent: Option[BillContent],
      failureCode: Option[Int],
      failureMessage: Option[String]
  )

  case class ImportBillArgs(token: String, billText: String)
  case class GetMyBillsArgs(token: String)
  case class BillWithProjects(bill: Bill, projects: List[Project])
  case class GetMyProjectsArgs(
      token: String,
      includeTypes: List[Int],
      active: Boolean
  )
  case class ProjectMemberExt(
      projectMember: ProjectMember,
      project: Project,
      loginUser: LoginUser
  )
  case class ProjectExt(
      project: Project,
      members: List[ProjectMemberExt],
      roles: List[ProjectRole]
  )
  case class CreateProjectArgs(
      token: String,
      billId: Int,
      projectType: Int,
      projectName: String,
      projectStatus: Int,
      pi: Option[String],
      remarks: Option[String],
      inheritDataFrom: Option[Int],
      inheritOrgFrom: Option[Int]
  )
  case class UpdateProjectArgs(
      token: String,
      projectId: Int,
      projectName: String,
      projectStatus: Int,
      pi: Option[String],
      remarks: Option[String]
  )
  case class CreateProjectMemberArgs(
      token: String,
      projectId: Int,
      userId: Int,
      roleName: String,
      permits: Int,
      active: Boolean,
      deleted: Boolean,
      displayName: Option[String],
      l1OrgId: Option[Int],
      l2OrgId: Option[Int],
      l3OrgId: Option[Int],
      remarks: Option[String],
      joinedAt: Option[Long]
  )
  case class UpdateProjectMemberArgs(
      token: String,
      projectId: Int,
      userId: Int,
      roleName: String,
      permits: Int,
      active: Boolean,
      deleted: Boolean,
      displayName: Option[String],
      l1OrgId: Option[Int],
      l2OrgId: Option[Int],
      l3OrgId: Option[Int],
      remarks: Option[String],
      joinedAt: Option[Long]
  )
  case class JoinProjectArgs(token: String, projectMemberId: Int)
  case class UpdateProjectMemberAsMemberArgs(
      token: String,
      projectId: Int,
      userId: Int,
      displayName: Option[String]
  )
  case class FindUserByUsernameArgs(token: String, usernameStartsWith: String)
  case class TransferProjectArgs(
      token: String,
      projectId: Int,
      transferToUserId: Int
  )
  case class LeaveProjectArgs(token: String, projectId: Int)
  case class GetOrganizationsByProjectArgs(token: String, projectId: Int)
  case class CreateOrganizationArgs(
      token: String,
      projectId: Int,
      orgLevel: Int,
      orgName: String,
      parentId: Option[Int]
  )
  case class UpdateOrganizationArgs(
      token: String,
      orgId: Int,
      orgLevel: Int,
      orgName: String,
      parentId: Option[Int]
  )
  case class AdminGetUserProjectMembersArgs(token: String, userId: Int)

  case class Queries(
      welcome: UIO[String],
      getCurrentUser: GetCurrentUserArgs => ZIO[Has[DataSourceProvider], Nothing, Response[User]],
      adminGetUsers: AdminGetUsersArgs => ZIO[Has[DataSourceProvider], Nothing, Response[Paged[UserWithProjects]]],
      validateBill: ValidateBillArgs => ZIO[Has[DataSourceProvider], Nothing, Response[BillValidation]],
      getMyBills: GetMyBillsArgs => ZIO[Has[DataSourceProvider], Nothing, Response[List[BillWithProjects]]],
      getMyProjects: GetMyProjectsArgs => ZIO[Has[DataSourceProvider], Nothing, Response[List[ProjectExt]]],
      getPermitsDefinition: ZIO[Has[DataSourceProvider], Nothing, Response[List[Permit]]],
      findUserByUsername: FindUserByUsernameArgs => ZIO[Has[DataSourceProvider], Nothing, Response[List[LoginUser]]],
      getOrganizationsByProject: GetOrganizationsByProjectArgs => ZIO[Has[DataSourceProvider], Nothing, Response[List[Organization]]],
      adminGetUserProjectMembers: AdminGetUserProjectMembersArgs => ZIO[Has[DataSourceProvider], Nothing, Response[List[ProjectMemberExt]]]
  )

  case class Mutations(
      login: LoginArgs => ZIO[Has[DataSourceProvider], Nothing, Response[UserWithToken]],
      vcode: VcodeArgs => ZIO[Has[DataSourceProvider], Nothing, Response[List[String]]],
      changePasswordByVcode: ChangePasswordByVcodeArgs => ZIO[Has[DataSourceProvider], Nothing, Response[Unit]],
      register: RegisterArgs => ZIO[Has[DataSourceProvider], Nothing, Response[User]],
      changePassword: ChangePasswordArgs => ZIO[Has[DataSourceProvider], Nothing, Response[Unit]],
      updateCurrentUser: UpdateCurrentUserArgs => ZIO[Has[DataSourceProvider], Nothing, Response[User]],
      logout: LogoutArgs => ZIO[Has[DataSourceProvider], Nothing, Response[Unit]],
      // adminChangePassword: AdminChangePasswordArgs => ZIO[Has[DataSourceProvider], Nothing, Response[Unit]],
      // adminVcode: AdminVcodeArgs => ZIO[Has[DataSourceProvider], Nothing, Response[UserWithVcode]],
      // adminUpdateUser: AdminUpdateUserArgs => ZIO[Has[DataSourceProvider], Nothing, Response[User]],
      // adminCreateUser: AdminCreateUserArgs => ZIO[Has[DataSourceProvider], Nothing, Response[User]],
      // importBill: ImportBillArgs => ZIO[Has[DataSourceProvider], Nothing, Response[Bill]],
      // createProject: CreateProjectArgs => ZIO[Has[DataSourceProvider], Nothing, Response[Project]]
      // updateProject: UpdateProjectArgs => ZIO[Has[DataSourceProvider], Nothing, Response[Project]]
      // createProjectMember: CreateProjectMemberArgs => ZIO[Has[DataSourceProvider], Nothing, Response[ProjectMember]],
      // updateProjectMember: UpdateProjectMemberArgs => ZIO[Has[DataSourceProvider], Nothing, Response[ProjectMember]]
      // joinProject: JoinProjectArgs => ZIO[Has[DataSourceProvider], Nothing, Response[ProjectMember]],
      // updateProjectMemberAsMember: UpdateProjectMemberAsMemberArgs => ZIO[Has[DataSourceProvider], Nothing, Response[ProjectMember]],
      transferProject: TransferProjectArgs => ZIO[Has[DataSourceProvider], Nothing, Response[Project]],
      leaveProject: LeaveProjectArgs => ZIO[Has[DataSourceProvider], Nothing, Response[Unit]],
      createOrganization: CreateOrganizationArgs => ZIO[Has[DataSourceProvider], Nothing, Response[Organization]],
      updateOrganization: UpdateOrganizationArgs => ZIO[Has[DataSourceProvider], Nothing, Response[Organization]]
  )

  case class Subscriptions(
  )

  val dataSourceProviderLayer: ULayer[Has[DataSourceProvider]] = ZLayer
    .fromEffectMany(
      Task.effect(DataSourceProvider.fallback).map(dsp => Has(dsp))
    )
    .orDie

  val dataSourceTask = Task.effect {
    println("creating datasource...")
    val source = ConfigFactory.load
    val config = new HikariConfig(propsFromConfigWithPrefix(source, "quill"))
    new HikariDataSource(config).asInstanceOf[DataSource]
  }

  val dbMigrationLayer: ZLayer[Has[DataSourceProvider], Nothing, Has[Unit]] =
    ZLayer.fromService(dsp =>
      Flyway
        .configure()
        .dataSource(dsp.getDataSource)
        .locations("classpath:db/migration")
        .load()
        .migrate()
    )

  val dataSourceLayer: ZLayer[Has[DataSourceProvider], Nothing, Has[DataSource]] =
    ZLayer.fromService(dsp => dsp.getDataSource)

  val runtimeDependencies: ULayer[Has[DataSourceProvider]] =
    dataSourceProviderLayer >+> dbMigrationLayer

  object GraphQL {

    def successOutcome = Outcome(true, 0, "")
    def mockResponse[T](data: T) = ZIO.succeed(Response(successOutcome, Some(data)))
    def mockUser: User = User(900001, 0, "user", "", "", None, true, None, System.currentTimeMillis)

    val queryResolver = Queries(
      welcome = ZIO.succeed(
        "This is a demo project to showcase the suspicious failure of Schema.gen."
      ),
      getCurrentUser = (args: GetCurrentUserArgs) => mockResponse(mockUser),
      adminGetUsers = (args: AdminGetUsersArgs) => mockResponse(Paged[UserWithProjects](0, 0, List())),
      validateBill = (args: ValidateBillArgs) => mockResponse(BillValidation(false, None, None, None)),
      getMyBills = (args: GetMyBillsArgs) => mockResponse(List[BillWithProjects]()),
      getMyProjects = (args: GetMyProjectsArgs) => mockResponse(List[ProjectExt]()),
      getPermitsDefinition = mockResponse(List[Permit]()),
      findUserByUsername = (args: FindUserByUsernameArgs) => mockResponse(List[LoginUser]()),
      getOrganizationsByProject = (args: GetOrganizationsByProjectArgs) => mockResponse(List[Organization]()),
      adminGetUserProjectMembers = (args: AdminGetUserProjectMembersArgs) => mockResponse(List[ProjectMemberExt]())
    )
    val mutationResolver = Mutations(
      login = (args: LoginArgs) => mockResponse(UserWithToken(mockUser, "")),
      vcode = (args: VcodeArgs) => mockResponse(List("")),
      changePasswordByVcode = (args: ChangePasswordByVcodeArgs) => mockResponse(()),
      register = (args: RegisterArgs) => mockResponse(mockUser),
      changePassword = (args: ChangePasswordArgs) => mockResponse(()),
      updateCurrentUser = (args: UpdateCurrentUserArgs) => mockResponse(mockUser),
      logout = (args: LogoutArgs) => mockResponse(()),
      // adminChangePassword = (args: AdminChangePasswordArgs) => mockResponse(()),
      // adminVcode = (args: AdminVcodeArgs) => mockResponse(UserWithVcode(mockUser, "", 0)),
      // adminUpdateUser = (args: AdminUpdateUserArgs) => mockResponse(mockUser),
      // adminCreateUser = (args: AdminCreateUserArgs) => mockResponse(mockUser),
      // importBill = (args: ImportBillArgs) => mockResponse(Bill(0, 0, 0, 0, "", "", "", 0, "", 0, None)),
      // createProject = (args: CreateProjectArgs) => mockResponse(Project(0, 0, 0, 0, 0, 0, 0, "", 0, None, None, 0))
      // updateProject = (args: UpdateProjectArgs) => mockResponse(Project(0, 0, 0, 0, 0, 0, 0, "", 0, None, None, 0))
      // createProjectMember = (args: CreateProjectMemberArgs) => mockResponse(ProjectMember(0, 0, 0, 0, 0, "", 0, false, false, None, None, None, None, None, None)),
      // updateProjectMember = (args: UpdateProjectMemberArgs) => mockResponse(ProjectMember(0, 0, 0, 0, 0, "", 0, false, false, None, None, None, None, None, None))
      // joinProject = (args: JoinProjectArgs) => mockResponse(ProjectMember(0, 0, 0, 0, 0, "", 0, false, false, None, None, None, None, None, None)),
      // updateProjectMemberAsMember = (args: UpdateProjectMemberAsMemberArgs) => mockResponse(ProjectMember(0, 0, 0, 0, 0, "", 0, false, false, None, None, None, None, None, None)),
      transferProject = (args: TransferProjectArgs) => mockResponse(Project(0, 0, 0, 0, 0, 0, 0, "", 0, None, None, 0)),
      leaveProject = (args: LeaveProjectArgs) => mockResponse(()),
      createOrganization = (args: CreateOrganizationArgs) => mockResponse(Organization(0, 0, 0, 0, 0, "", None)),
      updateOrganization = (args: UpdateOrganizationArgs) => mockResponse(Organization(0, 0, 0, 0, 0, "", None))
    )

    implicit val outcomeSchema: Schema[Any, Outcome] = Schema.gen
    implicit val responseUnitSchema: Schema[Any, Response[Unit]] = Schema.gen
    implicit val responseUserSchema: Schema[Any, Response[User]] = Schema.gen
    implicit val responseUserWithVcodeSchema: Schema[Any, Response[UserWithVcode]] = Schema.gen

    // hint from genDebug of queries
    implicit val getCurrentUserArgsSchema: Schema[Any, GetCurrentUserArgs] = Schema.gen
    implicit val adminGetUsersArgsSchema: Schema[Any, AdminGetUsersArgs] = Schema.gen
    implicit val validateBillArgsSchema: Schema[Any, ValidateBillArgs] = Schema.gen
    implicit val getMyBillsArgsSchema: Schema[Any, GetMyBillsArgs] = Schema.gen
    implicit val getMyProjectsArgsSchema: Schema[Any, GetMyProjectsArgs] = Schema.gen
    implicit val findUserByUsernameArgsSchema: Schema[Any, FindUserByUsernameArgs] = Schema.gen
    implicit val getOrganizationsByProjectArgsSchema: Schema[Any, GetOrganizationsByProjectArgs] = Schema.gen
    implicit val adminGetUserProjectMembersArgsSchema: Schema[Any, AdminGetUserProjectMembersArgs] = Schema.gen
    implicit val userWithProjectsSchema: Schema[Any, UserWithProjects] = Schema.gen
    implicit val pagedUserWithProjectsSchema: Schema[Has[DataSourceProvider], Paged[UserWithProjects]] = Schema.gen
    implicit val responsePagedUserWithProjectsSchema: Schema[Has[DataSourceProvider], Response[Paged[UserWithProjects]]] = Schema.gen
    implicit val responseBillValidationSchema: Schema[Has[DataSourceProvider], Response[BillValidation]] = Schema.gen
    implicit val billWithProjectsSchema: Schema[Any, BillWithProjects] = Schema.gen
    implicit val responseListBillWithProjectsSchema: Schema[Has[DataSourceProvider], Response[List[BillWithProjects]]] = Schema.gen
    implicit val projectSchema: Schema[Any, Project] = Schema.gen
    implicit val projectMemberSchema: Schema[Any, ProjectMember] = Schema.gen
    implicit val projectRoleSchema: Schema[Any, ProjectRole] = Schema.gen
    implicit val projectMemberExtSchema: Schema[Any, ProjectMemberExt] = Schema.gen
    implicit val projectExtSchema: Schema[Any, ProjectExt] = Schema.gen
    implicit val responseListProjectExtSchema: Schema[Has[DataSourceProvider], Response[List[ProjectExt]]] = Schema.gen
    implicit val responseListPermitSchema: Schema[Has[DataSourceProvider], Response[List[Permit]]] = Schema.gen
    implicit val loginUserSchema: Schema[Any, LoginUser] = Schema.gen
    implicit val responseListLoginUserSchema: Schema[Has[DataSourceProvider], Response[List[LoginUser]]] = Schema.gen
    implicit val organizationSchema: Schema[Any, Organization] = Schema.gen
    implicit val responseListOrganizationSchema: Schema[Has[DataSourceProvider], Response[List[Organization]]] = Schema.gen
    implicit val responseListProjectMemberExtSchema: Schema[Has[DataSourceProvider], Response[List[ProjectMemberExt]]] = Schema.gen

    // hint from genDebug of mutations
    implicit val adminVcodeArgsSchema: Schema[Any, AdminVcodeArgs] = Schema.gen
    implicit val adminChangePasswordArgsSchema: Schema[Any, AdminChangePasswordArgs] = Schema.gen
    implicit val logoutArgsSchema: Schema[Any, LogoutArgs] = Schema.gen
    implicit val updateCurrentUserArgsSchema: Schema[Any, UpdateCurrentUserArgs] = Schema.gen
    implicit val changePasswordArgsSchema: Schema[Any, ChangePasswordArgs] = Schema.gen
    implicit val registerArgsSchema: Schema[Any, RegisterArgs] = Schema.gen
    implicit val changePasswordByVcodeArgsSchema: Schema[Any, ChangePasswordByVcodeArgs] = Schema.gen
    implicit val vcodeArgsSchema: Schema[Any, VcodeArgs] = Schema.gen
    implicit val loginArgsSchema: Schema[Any, LoginArgs] = Schema.gen
    implicit val createProjectArgsSchema: Schema[Any, CreateProjectArgs] = Schema.gen
    implicit val updateProjectArgsSchema: Schema[Any, UpdateProjectArgs] = Schema.gen
    implicit val responseBillSchema: Schema[Has[DataSourceProvider], Response[Bill]] = Schema.gen
    implicit val responseProjectSchema: Schema[Has[DataSourceProvider], Response[Project]] = Schema.gen
    implicit val responseListStringSchema: Schema[Has[DataSourceProvider], Response[List[String]]] = Schema.gen
    implicit val responseUserWithTokenSchema: Schema[Has[DataSourceProvider], Response[UserWithToken]] = Schema.gen

    implicit val ImportBillArgsSchema: Schema[Any, ImportBillArgs] = Schema.gen
    implicit val createProjectMemberArgsSchema: Schema[Any, CreateProjectMemberArgs] = Schema.gen
    implicit val updateProjectMemberArgsSchema: Schema[Any, UpdateProjectMemberArgs] = Schema.gen

    implicit val queriesSchema: Schema[Has[DataSourceProvider], Queries] = Schema.gen
    implicit val mutationsSchema: Schema[Has[DataSourceProvider], Mutations] = Schema.genDebug

    val api = graphQL(RootResolver(queryResolver, mutationResolver))
  }

  import zhttp.http.*
  import zhttp.service.Server
  import caliban.ZHttpAdapter
  import zhttp.service.Server

  import zhttp.http.Middleware.cors
  import zhttp.http.middleware.Cors.CorsConfig
  val config: CorsConfig =
    CorsConfig(
      allowedOrigins = _ => true,
      allowedMethods = Some(Set(Method.PUT, Method.POST, Method.GET, Method.DELETE))
    )

  val graphQLServer =
    for {
      interpreter <- GraphQL.api.interpreter
      out <- interpreter.execute("""{welcome}""")
      _ <- putStrLn(s"GraphQL interpreter built. Sample query result: $out.")
      _ <- putStrLn(
        s"Starting HTTP server @ http://localhost:9999/api/graphql & WebSocket server @ ws://localhost:9999/ws/graphql"
      )
      _ <- Server
        .start(
          9999,
          Http.route[Request] {
            case _ -> !! / "api" / "graphql" =>
              ZHttpAdapter.makeHttpService(interpreter)
            case _ -> !! / "ws" / "graphql" =>
              ZHttpAdapter.makeWebSocketService(interpreter)
          } @@ cors(config)
        )
        .forever
    } yield ()

  def run(args: List[String]) =
    graphQLServer.provideCustomLayer(runtimeDependencies).exitCode
