Option Compare Text
Imports System.Data.OleDb
Imports System.Web.Script.Serialization
Imports System.Data.SqlClient

'*** 2021-12-22 library class for Admin pages rev 1
'*** 2021-12-22 bug fix reactivate users - they were being redacted if their auditstate was expired
'*** strictly though, to reactivate then we need a new audit=verified.  if we don't do this, and their audit=expired >150 days, they will be deregistered immediately.

Public Class Admin_class

    '*** these structs define permitted states, and are available fully qualified across all the other forms
    '*** will ensure consistency when invoking state changes which are stored as a string in the database.
    '*** https://stackoverflow.com/questions/12312325/define-string-enum-in-vb-net

    Structure UserState
        Const INACTIVE = "inactive"
        Const PENDINGADMIN = "pendingadmin"
        Const ACTIVE = "active"
        Const DEREGISTERED = "deregistered"
        Const REACTIVATE = "reactivate"
    End Structure

    Structure AuditState
        Const VERIFIED = "verified"
        Const AUDIT = "audit"
        Const REVOKED = "revoked"
        Const EXPIRED = "expired"

    End Structure


    'used to hold common methods
    ReadOnly sConn As String = ConfigurationManager.ConnectionStrings("sConn").ConnectionString
    Public Property pg As Page
    Public Sub setPage(userPg As Page)
        pg = userPg
    End Sub
    Sub doUserLifecycle()

        '*** 2020-10-20 perform bulk updates on user auditStatus and userStatus
        '*** to avoid the Admins getting locked out, this is handled in the showGUI, except that user 90 day locks are automatic in the checkLogonUser routine

        '*** 2021-1-8 pg is optional, this allows code re-use when calling from a ashx handler

        If Not pg Is Nothing Then pg.Trace.Warn("doUserLifecyle  " & Format(Now, "yyyy-MM-dd"))
        '*** userStates are:
        'pendingAdmin - pending admin activation
        'active - user active
        'inactive - no login for 90 days, after 120 days account is deregistered [amber]
        'reactivate - inactive user has asked to be reactivated [amber, red attn flag]
        'deregistered - redacted ex user [grey]

        '**** auditStates are:
        'verified  [green]
        'revoked - need to deregister user  [grey]
        'audit - pending audit after 90 days  [amber]
        'expired - 120 days expired, causes user=deregistered [red]
        'Note: expired accounts have another 30days in which their owner can hassle management to reinstate them.  After this the user is deregistered.

        'note on registration.  for new users, no authUser entry exists in db. we create a record with userState=register
        'for re-registration, authUser exists and we have to check user was deregistered first before allowing the record to be updated to userState=register

        '++++++++++++++++++++++++
        'security issues.  If Admin accounts don't end up locked or de-registered, then the admin user can continue to operate under their existing
        'profile unabated.  Except the main screens will see a negative result for checkLoginUser and thus redirect to the admin screeen
        'where the admin will only be able to perform admin functions. note that their last login date does NOT get updated because they failed the 
        'checkLogonUser screen earlier
        '++++++++++++++++++++++++++

        'Note 2020-10-26 any newly registered user will have a null lastLoginUTC and auditLastDate.  Need to check for this in the processing

        Dim oConn As New OleDb.OleDbConnection(sConn)
        Try
            '*** 2021-12-22 bug fix, do not process userState=reactivate.  This caused reactivate requests to be killed if the audit state had reached revoked.
            '*** Do Not process revoked users, pending users or deregistered ones
            Dim oDA As New OleDb.OleDbDataAdapter(String.Concat("SELECT * FROM tblUserPermission WHERE NOT (auditState='", AuditState.REVOKED, "' OR userState='", UserState.PENDINGADMIN, "'OR userState='", UserState.REACTIVATE, "' OR userState='", UserState.DEREGISTERED, "')"), oConn)

            Dim oDS As New DataSet
            oDA.Fill(oDS, "tblUser")

            Dim builder As OleDbCommandBuilder = New OleDbCommandBuilder(oDA)

            For Each myR As DataRow In oDS.Tables("tblUser").Rows
                '*** AUDIT driven.
                '*** Do Not modify users where auditstate=revoked because their manager chose to revoke them.
                '*** deregister users who's auditState is expired beyond 150 days.  Do NOT do this for admin users
                '*** if dt1 is more recent that dt2 the result is negative
                If IsDate(myR("auditLastDate")) Then
                    If DateDiff(DateInterval.Day, myR("auditLastDate"), DateTime.UtcNow) > 150 Then
                        '*** de-register and redact users at 150 days lasped audit
                        If myR("accountType") = "user" Then
                            myR("auditState") = AuditState.EXPIRED
                            myR("userState") = UserState.DEREGISTERED
                            myR("requestComment") = "user de-registered due to lapsed access audit"
                            myR("fullname") = "redacted"
                        End If
                        '*** expire users at 120 days lapsed audit
                    ElseIf DateDiff(DateInterval.Day, myR("auditLastDate"), DateTime.UtcNow) > 120 Then
                        myR("auditState") = AuditState.EXPIRED
                        '*** require an access audit at 90 days
                    ElseIf DateDiff(DateInterval.Day, myR("auditLastDate"), DateTime.UtcNow) > 90 Then
                        myR("auditState") = AuditState.AUDIT
                    End If
                Else
                    '*** 2021-1-7 do what if there is no auditLastDate?   Newly registered users will stay with this null indefinately.
                    '*** the safest option is to set a last audit date of today minus 90 days
                    myR("auditLastDate") = DateTime.UtcNow.AddDays(-90)
                End If

                '*** LAST LOGIN driven.
                '*** Ignore any users just de-registered. Do Not de-register admin users.
                If myR("userState") <> UserState.DEREGISTERED Then
                    If IsDate(myR("LastLoginUTC")) Then
                        If DateDiff(DateInterval.Day, myR("LastLoginUTC"), DateTime.UtcNow) > 120 Then
                            If myR("accountType") = "user" Then
                                myR("userState") = UserState.DEREGISTERED
                                myR("requestComment") = "lapsed user deregistered at 120 days"
                                myR("fullname") = "redacted"
                            End If
                        ElseIf myR("userState") = UserState.REACTIVATE Then
                            '*** special case for reactivate during 90-120 day window
                            '*** 2021-12-22 if reactivate user has expired audit, peg this back to today minus 90.  If we don't then
                            '*** as soon as the user is set to active, their expired audit (e.g. >150 days) will deregister them immediately!
                            If myR("auditState") = AuditState.EXPIRED Then
                                '*** so they now pending an audit.
                                myR("auditLastDate") = DateTime.UtcNow.AddDays(-90)
                                myR("auditState") = AuditState.AUDIT
                            End If


                        ElseIf DateDiff(DateInterval.Day, myR("LastLoginUTC"), DateTime.UtcNow) > 90 Then
                            myR("userState") = UserState.INACTIVE
                            myR("requestComment") = "inactive user account locked at 90 days"
                        End If
                    End If
                    '*** ignore records where LastLoginUTC is null
                End If
            Next

            builder.GetUpdateCommand()
            '*** This next line skips any errored fields
            oDA.ContinueUpdateOnError = "true"
            '***  Without the OleDbCommandBuilder this next line would fail.
            oDA.Update(oDS, "tblUser")

            '*** in summary, a lapsed user will expire their login at 120 days and be de-registered from this before their auditStatus causes them to be deregistered
            '*** so their manager may keep approving their audit but the user themselves is lapsed
            '*** the converse situation is a manager who fails to sign off an audit for 150 days will cause all his users to be deregistered, even if they are active

            '*** 2021-1-7 all users (user or admin) need to be de-registered if they are auditState=revoked
            Dim oCmd As New OleDb.OleDbCommand(String.Concat("UPDATE tblUserPermission SET userState='", UserState.DEREGISTERED, "' WHERE auditState='", AuditState.REVOKED, "'"), oConn)
            oConn.Open()
            oCmd.ExecuteNonQuery()
            oConn.Close()

            'now redact all deregistered users
            oCmd = New OleDb.OleDbCommand(String.Concat("UPDATE tblUserPermission SET fullname='redacted' WHERE userState='", UserState.DEREGISTERED, "'"), oConn)
            oConn.Open()
            oCmd.ExecuteNonQuery()
            oConn.Close()


            '*** force a refresh of the session vars because we may have impacted this user
            If Not pg Is Nothing Then pg.checkLogonUser(oConn, True, False, "qryPermission")


        Catch ex As Exception
            If Not pg Is Nothing Then pg.Trace.Warn(ex.ToString)
            writeAudit(ex.ToString, "doUserLifecyle")
        Finally
            oConn.Dispose()
        End Try

        If Not pg Is Nothing Then pg.Trace.Warn("exit doUserLifecyle")
    End Sub
    ''' <summary>
    ''' Call out to myhandler.ashx page to process alerts to Admins for new users and audit access
    ''' sAHandler is the handler page (relative) or from server root if given a leading forward slash
    ''' console will show result on page load
    ''' call just after you instantiate the admin object
    ''' </summary>
    ''' <param name="sHandler"></param>
    Sub checkNeedForAccessAudit(sHandler As String)
        If pg.IsPostBack Then Return

        '*** register a script to call .ashx which will alert Admins if an access audit is required
        'https//www.tutorialspoint.com/prototype/prototype_ajax_request.htm
        'https://stackoverflow.com/questions/14519757/how-to-call-ashx-handler-and-getting-the-result-back

        Dim script As String = "new Ajax.Request('" & sHandler & "', {method: 'get', onSuccess: function(response){if (console) console.log(response.responseText); }   });"
        pg.ClientScript.RegisterClientScriptBlock(GetType(String), "alert", script, True)

        '*** note, example below shows use of onSuccess and onFailure
        ' Dim script As String = "new Ajax.Request('/Admin_handler.ashx', {
        'method: 'get',
        'onSuccess: function (response) {
        '         alert(response.responseText);
        '      },
        'onFailure: function () {alert('oh dear')}       });"

    End Sub


    Function handler_checkStatus() As String
        '*** checks status of system, returns a serialised JSON string, called from the ashx handler, but coded in this module to consolidate code to one place
        Dim json As New List(Of Object)()
        Dim oConn As New OleDb.OleDbConnection(sConn)

        Dim xmlPath As String = ConfigurationManager.AppSettings.Get("strUserFiles").ToString
        xmlPath &= "/track.xml"

        Dim oDS As New DataSet
        Dim dr As DataRow

        Dim blEmitStatus As Boolean = False

        Try
            '*** create log file if not present
            If System.IO.File.Exists(xmlPath) = False Then
                oDS.Tables.Add("log")
                oDS.Tables("log").Columns.Add(New DataColumn("AdminDatePoint", GetType(String)))

                '*** if creating from a table rather than a dataset, ensure you writeschema
                'dt.WriteXml(xmlPath, XmlWriteMode.WriteSchema)  didn't work on a datatable
                oDS.WriteXml(xmlPath)
            End If


            oDS.ReadXml(xmlPath)

            With oDS.Tables("log")
                If .Rows.Count = 0 Then
                    '*** create user if required
                    dr = .NewRow
                    dr("AdmindatePoint") = Format(DateTime.UtcNow, "yyyy-MM-dd hh:mm")
                    .Rows.Add(dr)
                    blEmitStatus = True
                Else
                    '*** If the date is >24hours old, then update it and flag we need to emit status
                    dr = .Rows(0)
                    If CDate(dr("AdminDatePoint")) < DateTime.UtcNow.AddDays(-1) Then
                        blEmitStatus = True
                        dr("AdminDatePoint") = Format(DateTime.UtcNow, "yyyy-MM-dd hh:mm")
                    End If

                End If

                .WriteXml(xmlPath)
            End With



            '*** now, if we need to emit a status message, we need to check whether Access audits are pending, or user requests are pending
            If blEmitStatus = False Then
                json.Add(New With {.AdminDatePoint = dr("AdminDatePoint")})
                json.Add(New With {.Status = "no action"})
                json.Add(New With {.UserWarnings = "none"})

            Else
                '*** no more than once in every 24h....
                json.Add(New With {.AdminDatePoint = dr("AdminDatePoint")})


                'admin class does not use AdminAction field
                'Dim oCmd As New OleDb.OleDbCommand("SELECT COUNT(AdminAction) FROM tblUserPermission WHERE AdminAction=true;", oConn)

                Dim oCmd As New OleDb.OleDbCommand("SELECT COUNT(AuthUser) FROM tblUserPermission WHERE (userState='pendingAdmin' OR userstate='reactivate');", oConn)

                oConn.Open()
                Dim uCount As Long = oCmd.ExecuteScalar

                oCmd = New OleDb.OleDbCommand("SELECT COUNT(AuditState) FROM tblUserPermission WHERE AuditState='audit';", oConn)
                Dim aCount As Long = oCmd.ExecuteScalar
                oConn.Close()

                If uCount + aCount = 0 Then
                    json.Add(New With {.Status = "no action"})

                Else
                    json.Add(New With {.Status = "action"})
                    json.Add(New With {.uCount = uCount})
                    json.Add(New With {.aCount = aCount})


                    '*** craft a message
                    Dim title As String = ConfigurationManager.AppSettings("AppName") & " has pending admin actions"
                    Dim msg As String = uCount & " users have pending access requests, and " & aCount & " users require an access audit"


                    Dim dt As New DataTable
                    Dim oDA As New OleDb.OleDbDataAdapter("SELECT * FROM tblUserPermission WHERE accountType='admin';", sConn)
                    oDA.Fill(dt)

                    For Each myR As DataRow In dt.Rows
                        '*** get admin user LDAP 
                        Dim dtLDAP As DataTable = getLDAP(myR("Authuser"))
                        If dtLDAP.Rows.Count = 1 Then
                            sendMail(dtLDAP.Rows(0)("mail").ToString, "", "PCMnoReplies@verizon.com", title, msg)
                        End If
                    Next

                End If


                '*** 2022-01-04 warn users whose lastlogin was >80 days.  At 90 days they are made inactive which requires them to re-register.
                Dim oDAu As New OleDb.OleDbDataAdapter("SELECT * FROM tblUserPermission WHERE accountType='user' AND userState='ACTIVE' AND lastloginUTC<@p1;", sConn)
                oDAu.SelectCommand.Parameters.Add("@p1", OleDb.OleDbType.Date).Value = DateTime.UtcNow.AddDays(-80)

                Dim dtu As New DataTable
                oDAu.Fill(dtu)
                json.Add(New With {.UserWarnings = dtu.Rows.Count})

                For Each myR As DataRow In dtu.Rows
                    '*** warn each user
                    Dim dtLDAP As DataTable = getLDAP(myR("Authuser"))
                    If dtLDAP.Rows.Count = 1 Then
                        sendMail(dtLDAP.Rows(0)("mail").ToString, "", "PCMnoReplies@verizon.com",
                        ConfigurationManager.AppSettings("AppName") & " your access will expire soon",
                        "Warning: Your login will expire after 90 days of no activity.  Please login now to avoid losing access.")
                    End If
                Next

            End If


            Return New JavaScriptSerializer().Serialize(json)


        Catch ex As Exception
            writeAudit("handler_checkStatus " & ex.ToString, "system")
            Return Nothing
        Finally
            oDS.Dispose()
        End Try



    End Function

End Class
Public Class Admin_classSQL
    '*** SQL version of the same class
    '*** these structs define permitted states, and are available fully qualified across all the other forms
    '*** will ensure consistency when invoking state changes which are stored as a string in the database.
    '*** https://stackoverflow.com/questions/12312325/define-string-enum-in-vb-net

    Structure UserState
        Const INACTIVE = "inactive"
        Const PENDINGADMIN = "pendingadmin"
        Const ACTIVE = "active"
        Const DEREGISTERED = "deregistered"
        Const REACTIVATE = "reactivate"
    End Structure

    Structure AuditState
        Const VERIFIED = "verified"
        Const AUDIT = "audit"
        Const REVOKED = "revoked"
        Const EXPIRED = "expired"

    End Structure
    ''' <summary>
    ''' Create a new SQL admin object.  You can intialise its variables through the constructor, including if you declare as a global to the page class
    ''' </summary>
    ''' <param name="sConn"></param>
    ''' <param name="pg"></param>
    Public Sub New(Optional ByVal sConn As String = "", Optional ByRef pg As Page = Nothing)
        '*** can intialise these variables through the constructor.
        If Not String.IsNullOrEmpty(sConn) Then _sConn = sConn
        If Not pg Is Nothing Then _pg = pg

    End Sub
    Private _sConn As String
    Public Property ConnectionString() As String
        Set(value As String)
            _sConn = value
        End Set
        Get
            Return _sConn
        End Get

    End Property

    Private _pg As Page
    Public WriteOnly Property Page() As Page
        Set(value As Page)
            _pg = value
        End Set
    End Property


    ''' <summary>
    ''' Call out to myhandler.ashx page to process alerts to Admins for new users and audit access
    ''' sAHandler is the handler page (relative) or from server root if given a leading forward slash
    ''' console will show result on page load
    ''' call just after you instantiate the admin object
    ''' </summary>
    ''' <param name="sHandler"></param>
    Sub checkNeedForAccessAudit(sHandler As String)
        If _pg.IsPostBack Then Return

        '*** 2020-02-28 rethink - why make the page call an ashx handler, why not just run that code here?
        '*** it only runs once on page load anyway


        '*** register a script to call .ashx which will alert Admins if an access audit is required
        'https//www.tutorialspoint.com/prototype/prototype_ajax_request.htm
        'https://stackoverflow.com/questions/14519757/how-to-call-ashx-handler-and-getting-the-result-back

        Dim script As String = "new Ajax.Request('" & sHandler & "', {method: 'get', onSuccess: function(response){if (console) console.log(response.responseText); }   });"
        _pg.ClientScript.RegisterClientScriptBlock(GetType(String), "alert", script, True)

        '*** note, example below shows use of onSuccess and onFailure
        ' Dim script As String = "new Ajax.Request('/Admin_handler.ashx', {
        'method: 'get',
        'onSuccess: function (response) {
        '         alert(response.responseText);
        '      },
        'onFailure: function () {alert('oh dear')}       });"

    End Sub
    Function handler_checkStatus() As String
        '*** checks status of system, returns a serialised JSON string, called from the ashx handler, but coded in this module to consolidate code to one place
        Dim json As New List(Of Object)()
        Dim oConn As New SqlConnection(_sConn)

        Dim xmlPath As String = ConfigurationManager.AppSettings.Get("strUserFiles").ToString
        xmlPath &= "/track.xml"

        Dim oDS As New DataSet
        Dim dr As DataRow

        Dim blEmitStatus As Boolean = False

        Try
            '*** create log file if not present
            If System.IO.File.Exists(xmlPath) = False Then
                oDS.Tables.Add("log")
                oDS.Tables("log").Columns.Add(New DataColumn("AdminDatePoint", GetType(String)))

                '*** if creating from a table rather than a dataset, ensure you writeschema
                'dt.WriteXml(xmlPath, XmlWriteMode.WriteSchema)  didn't work on a datatable
                oDS.WriteXml(xmlPath)
            End If


            oDS.ReadXml(xmlPath)

            With oDS.Tables("log")
                If .Rows.Count = 0 Then
                    '*** create user if required
                    dr = .NewRow
                    dr("AdmindatePoint") = Format(DateTime.UtcNow, "yyyy-MM-dd hh:mm")
                    .Rows.Add(dr)
                    blEmitStatus = True
                Else
                    '*** If the date is >24hours old, then update it and flag we need to emit status
                    dr = .Rows(0)
                    If CDate(dr("AdminDatePoint")) < DateTime.UtcNow.AddDays(-1) Then
                        blEmitStatus = True
                        dr("AdminDatePoint") = Format(DateTime.UtcNow, "yyyy-MM-dd hh:mm")
                    End If

                End If

                .WriteXml(xmlPath)
            End With



            '*** now, if we need to emit a status message, we need to check whether Access audits are pending, or user requests are pending
            If blEmitStatus = False Then
                json.Add(New With {.AdminDatePoint = dr("AdminDatePoint")})
                json.Add(New With {.Status = "no action"})
                json.Add(New With {.UserWarnings = "none"})

            Else
                '*** no more than once in every 24h....
                json.Add(New With {.AdminDatePoint = dr("AdminDatePoint")})


                'admin class does not use AdminAction field
                'Dim oCmd As New OleDb.OleDbCommand("SELECT COUNT(AdminAction) FROM tblUserPermission WHERE AdminAction=true;", oConn)

                Dim oCmd As New SqlCommand("SELECT COUNT(AuthUser) FROM tblUserPermission WHERE (userState='pendingAdmin' OR userstate='reactivate');", oConn)

                oConn.Open()
                Dim uCount As Long = oCmd.ExecuteScalar

                oCmd = New SqlCommand("SELECT COUNT(AuditState) FROM tblUserPermission WHERE AuditState='audit';", oConn)
                Dim aCount As Long = oCmd.ExecuteScalar
                oConn.Close()

                If uCount + aCount = 0 Then
                    json.Add(New With {.Status = "no action"})

                Else
                    json.Add(New With {.Status = "action"})
                    json.Add(New With {.uCount = uCount})
                    json.Add(New With {.aCount = aCount})


                    '*** craft a message
                    Dim title As String = ConfigurationManager.AppSettings("AppName") & " has pending admin actions"
                    Dim msg As String = uCount & " users have pending access requests, and " & aCount & " users require an access audit"


                    Dim dt As New DataTable
                    Dim oDA As New SqlDataAdapter("SELECT * FROM tblUserPermission WHERE accountType='admin';", _sConn)
                    oDA.Fill(dt)

                    For Each myR As DataRow In dt.Rows
                        '*** get admin user LDAP 
                        Dim dtLDAP As DataTable = getLDAP(myR("Authuser"))
                        If dtLDAP.Rows.Count = 1 Then
                            sendMail(dtLDAP.Rows(0)("mail").ToString, "", "PCMnoReplies@verizon.com", title, msg)
                        End If
                    Next

                End If


                '*** 2022-01-04 warn users whose lastlogin was >80 days.  At 90 days they are made inactive which requires them to re-register.
                Dim oDAu As New SqlDataAdapter("SELECT * FROM tblUserPermission WHERE accountType='user' AND userState='ACTIVE' AND lastloginUTC<@p1;", _sConn)
                'oDAu.SelectCommand.Parameters.Add("@p1", SqlDbType.Date).Value = DateTime.UtcNow.AddDays(-80)
                oDAu.SelectCommand.Parameters.AddWithValue("@p1", DateTime.UtcNow.AddDays(-80))


                Dim dtu As New DataTable
                oDAu.Fill(dtu)
                json.Add(New With {.UserWarnings = dtu.Rows.Count})

                For Each myR As DataRow In dtu.Rows
                    '*** warn each user
                    Dim dtLDAP As DataTable = getLDAP(myR("Authuser"))
                    If dtLDAP.Rows.Count = 1 Then
                        sendMail(dtLDAP.Rows(0)("mail").ToString, "", "PCMnoReplies@verizon.com",
                        ConfigurationManager.AppSettings("AppName") & " your access will expire soon",
                        "Warning: Your login will expire after 90 days of no activity.  Please login now to avoid losing access.")
                    End If
                Next

            End If


            Return New JavaScriptSerializer().Serialize(json)


        Catch ex As Exception
            writeAudit("handler_checkStatus " & ex.ToString, "system")
            Return Nothing
        Finally
            oDS.Dispose()
        End Try



    End Function
    ''' <summary>
    ''' handles user authentication and audit status lifecycle.  Calls checkLogonUser and expects qryPermission to exist, this query will provide
    ''' support for profiles.  This call is made only to refresh session vars if user status has changed.  You should call checkLogonUser per page serve
    ''' independently of this
    ''' </summary>
    Sub doUserLifecycle()
        '*** 2022-02-25 ported to SQLserver

        '*** 2020-10-20 perform bulk updates on user auditStatus and userStatus
        '*** to avoid the Admins getting locked out, this is handled in the showGUI, except that user 90 day locks are automatic in the checkLogonUser routine

        '*** 2021-1-8 pg is optional, this allows code re-use when calling from a ashx handler

        If Not _pg Is Nothing Then _pg.Trace.Warn("doUserLifecyle  " & Format(Now, "yyyy-MM-dd") & "  " & _sConn)
        '*** userStates are:
        'pendingAdmin - pending admin activation
        'active - user active
        'inactive - no login for 90 days, after 120 days account is deregistered [amber]
        'reactivate - inactive user has asked to be reactivated [amber, red attn flag]
        'deregistered - redacted ex user [grey]

        '**** auditStates are:
        'verified  [green]
        'revoked - need to deregister user  [grey]
        'audit - pending audit after 90 days  [amber]
        'expired - 120 days expired, causes user=deregistered [red]
        'Note: expired accounts have another 30days in which their owner can hassle management to reinstate them.  After this the user is deregistered.

        'note on registration.  for new users, no authUser entry exists in db. we create a record with userState=register
        'for re-registration, authUser exists and we have to check user was deregistered first before allowing the record to be updated to userState=register

        '++++++++++++++++++++++++
        'security issues.  If Admin accounts don't end up locked or de-registered, then the admin user can continue to operate under their existing
        'profile unabated.  Except the main screens will see a negative result for checkLoginUser and thus redirect to the admin screeen
        'where the admin will only be able to perform admin functions. note that their last login date does NOT get updated because they failed the 
        'checkLogonUser screen earlier
        '++++++++++++++++++++++++++

        'Note 2020-10-26 any newly registered user will have a null lastLoginUTC and auditLastDate.  Need to check for this in the processing

        Dim oConn As New SqlConnection(_sConn)
        Try
            '*** 2021-12-22 bug fix, do not process userState=reactivate.  This caused reactivate requests to be killed if the audit state had reached revoked.
            '*** Do Not process revoked users, pending users or deregistered ones
            ' Dim oDA As New SqlDataAdapter(String.Concat("SELECT * FROM tblUserPermission WHERE NOT (auditState='", AuditState.REVOKED, "' OR userState='", UserState.PENDINGADMIN, "'OR userState='", UserState.REACTIVATE, "' OR userState='", UserState.DEREGISTERED, "')"), oConn)

            Dim oDA As New SqlDataAdapter("SELECT * FROM tblUserPermission WHERE NOT (auditState=@p1 OR userState=@p2 OR userState=@p3 OR userState=@p4);", oConn)
            oDA.SelectCommand.Parameters.AddWithValue("@p1", AuditState.REVOKED)
            oDA.SelectCommand.Parameters.AddWithValue("@p2", UserState.PENDINGADMIN)
            oDA.SelectCommand.Parameters.AddWithValue("@p3", UserState.REACTIVATE)
            oDA.SelectCommand.Parameters.AddWithValue("@p4", UserState.DEREGISTERED)


            Dim oDS As New DataSet
            oDA.Fill(oDS, "tblUser")

            Dim builder As SqlCommandBuilder = New SqlCommandBuilder(oDA)

            For Each myR As DataRow In oDS.Tables("tblUser").Rows
                '*** AUDIT driven.
                '*** Do Not modify users where auditstate=revoked because their manager chose to revoke them.
                '*** deregister users who's auditState is expired beyond 150 days.  Do NOT do this for admin users
                '*** if dt1 is more recent that dt2 the result is negative
                If IsDate(myR("auditLastDate")) Then
                    If DateDiff(DateInterval.Day, myR("auditLastDate"), DateTime.UtcNow) > 150 Then
                        '*** de-register and redact users at 150 days lasped audit
                        If myR("accountType") = "user" Then
                            myR("auditState") = AuditState.EXPIRED
                            myR("userState") = UserState.DEREGISTERED
                            myR("requestComment") = "user de-registered due to lapsed access audit"
                            myR("fullname") = "redacted"
                        End If
                        '*** expire users at 120 days lapsed audit
                    ElseIf DateDiff(DateInterval.Day, myR("auditLastDate"), DateTime.UtcNow) > 120 Then
                        myR("auditState") = AuditState.EXPIRED
                        '*** require an access audit at 90 days
                    ElseIf DateDiff(DateInterval.Day, myR("auditLastDate"), DateTime.UtcNow) > 90 Then
                        myR("auditState") = AuditState.AUDIT
                    End If
                Else
                    '*** 2021-1-7 do what if there is no auditLastDate?   Newly registered users will stay with this null indefinately.
                    '*** the safest option is to set a last audit date of today minus 90 days
                    myR("auditLastDate") = DateTime.UtcNow.AddDays(-90)
                End If

                '*** LAST LOGIN driven.
                '*** Ignore any users just de-registered. Do Not de-register admin users.
                If myR("userState") <> UserState.DEREGISTERED Then
                    If IsDate(myR("LastLoginUTC")) Then
                        If DateDiff(DateInterval.Day, myR("LastLoginUTC"), DateTime.UtcNow) > 120 Then
                            If myR("accountType") = "user" Then
                                myR("userState") = UserState.DEREGISTERED
                                myR("requestComment") = "lapsed user deregistered at 120 days"
                                myR("fullname") = "redacted"
                            End If
                        ElseIf myR("userState") = UserState.REACTIVATE Then
                            '*** special case for reactivate during 90-120 day window
                            '*** 2021-12-22 if reactivate user has expired audit, peg this back to today minus 90.  If we don't then
                            '*** as soon as the user is set to active, their expired audit (e.g. >150 days) will deregister them immediately!
                            If myR("auditState") = AuditState.EXPIRED Then
                                '*** so they now pending an audit.
                                myR("auditLastDate") = DateTime.UtcNow.AddDays(-90)
                                myR("auditState") = AuditState.AUDIT
                            End If


                        ElseIf DateDiff(DateInterval.Day, myR("LastLoginUTC"), DateTime.UtcNow) > 90 Then
                            myR("userState") = UserState.INACTIVE
                            myR("requestComment") = "inactive user account locked at 90 days"
                        End If
                    End If
                    '*** ignore records where LastLoginUTC is null
                End If
            Next

            builder.GetUpdateCommand()
            '*** This next line skips any errored fields
            oDA.ContinueUpdateOnError = "true"
            '***  Without the OleDbCommandBuilder this next line would fail.
            oDA.Update(oDS, "tblUser")

            '*** in summary, a lapsed user will expire their login at 120 days and be de-registered from this before their auditStatus causes them to be deregistered
            '*** so their manager may keep approving their audit but the user themselves is lapsed
            '*** the converse situation is a manager who fails to sign off an audit for 150 days will cause all his users to be deregistered, even if they are active

            '*** 2021-1-7 all users (user or admin) need to be de-registered if they are auditState=revoked
            'Dim oCmd As New SqlCommand(String.Concat("UPDATE tblUserPermission SET userState='", UserState.DEREGISTERED, "' WHERE auditState='", AuditState.REVOKED, "'"), oConn)
            Dim oCmd As New SqlCommand("UPDATE tblUserPermission SET userState=@p1 WHERE auditState=@p2;", oConn)

            oCmd.Parameters.AddWithValue("@p1", UserState.DEREGISTERED)
            oCmd.Parameters.AddWithValue("@p2", AuditState.REVOKED)
            oConn.Open()
            oCmd.ExecuteNonQuery()
            oConn.Close()

            'now redact all deregistered users
            'oCmd = New SqlCommand(String.Concat("UPDATE tblUserPermission SET fullname='redacted' WHERE userState='", UserState.DEREGISTERED, "'"), oConn)
            oCmd = New SqlCommand("UPDATE tblUserPermission SET fullname='redacted' WHERE userState=@p1;", oConn)
            oCmd.Parameters.AddWithValue("@p1", UserState.DEREGISTERED)
            oConn.Open()
            oCmd.ExecuteNonQuery()
            oConn.Close()


            '*** force a refresh of the session vars because we may have impacted this user
            If Not _pg Is Nothing Then _pg.checkLogonUser(oConn, True, False, "qryPermission")


        Catch ex As Exception
            If Not _pg Is Nothing Then _pg.Trace.Warn(ex.ToString)
            writeAudit(ex.ToString, "doUserLifecyle")
        Finally
            oConn.Dispose()
        End Try

        If Not _pg Is Nothing Then _pg.Trace.Warn("exit doUserLifecyle")
    End Sub



End Class
