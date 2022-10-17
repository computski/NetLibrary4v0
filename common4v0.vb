Imports System.Text.RegularExpressions
Imports System.Runtime.CompilerServices
Imports System.IO
Imports System.Data.SqlClient
'*** DirectoryServices is required for LDAP
Imports System.DirectoryServices.AccountManagement
Imports System.DirectoryServices
Imports System.Data.OleDb
Imports System.Runtime.Serialization
Imports System.Runtime.Serialization.Formatters.Binary
'**** Important: do not copy this library to your project, instead use Add As Link when adding an existing item.

Module common
    '*** VERSION 3.5 with extension methods and SQLserver support, for use with LDAP
    '*** 2014-05-28 rewritten as ASP.NET 2
    '*** 2014-06-15 modified to simplify CheckSession and to make it work with a general local permission table
    '*** 2014-06-27 bug fix in SendMail addresses need to be added individually.  semicolon separated addresses not valid.
    '*** 2014-09-03 CP810 cookie timeout added in CheckSession
    '*** 2014-11-04 StreamFile added
    '*** 2014-11-04 exportRFC4180table added
    '*** 2014-11-06 fixed bug in CheckSession, it needs to check all session vars are present
    '*** 2014-11-17 updated setDropDown to work like doBindDataRow, changed connection string to sConn
    '*** 2014-11-20 added sortACDC overload to handle datagrids
    '*** 2014-11-25 added setGVcolVis
    '*** 2014-11-17 Note: doBindDataRow and doUnbindDataRow work with a lookHere object, this could be a page, a DataGridRow or a GridView row
    '*** 2015-04-29 added checkNTLMUser
    '*** 2015-05-04 added setColVis overload to handle column visibility on datagrids and gridview.  setDGcolVis/ setGVcolVis are deprecated
    '*** 2015-06-09 added blPathInfo to checkNTLMuser as a means of cleaning up URLs with appended target info
    '*** 2015-06-19 checkNTLMUser supports tblName as the permissions table, must be Read/Write
    '*** 2015-07-03 bug fix.  Users > 120 days inactive OR with NULL LastLoginUTC will return false
    '*** 2015-09-17 checkNTLMuser will return false if AccountLocked=true
    '*** 2015-09-21 streamfile updated to write to log and not reveal path info on error
    '*** 2016-09-09 bugfix checkNTLMuser where lastLoginUTC is null 
    '*** 2018-03-21 added HttpUtility.HTMLEncode(string) in the doBindDataRow routine to protect against cross site script attack XSS
    '*** [have i doubled up?  i use doBindDataRow on form fields such as fld_ so there is no need to use fnAsHTML on these too, however i do
    '*** need to use fnAsHTML on a datagrid as this is bound from a dataset, not thro fnASHTML]
    '*** 2018-03-26 added urldecode to pathinfo in checkNTLMuser
    '*** 2018-04-27 added checkLogonUser
    '*** 2018-10-18 added dtColumnOrder
    '*** 2018-11-20 converted many routines to Extension References. 
    '*** https://docs.microsoft.com/en-us/dotnet/visual-basic/programming-guide/language-features/procedures/extension-methods
    '*** 2019-01-21 added extension method for postedfile to datatable for csv parsing
    '*** 2019-01-23 added CTypeOrFail as a graceful-error type conversion method for use with csv parsing
    '*** 2019-01-23 Streamfile updated to fix threadAbortException
    '*** 2019-02-15 Streamfile modified because .response.end() is harmful
    '*** 2019-02-20 checkLogonUser made an extension method
    '*** 2019-02-20 removed all deprecated code
    '*** 2019-03-13 Streamfile and ExportRFC fixed to avoid use of response.end
    '*** 2019-04-29 converted to support SQL server
    '*** 2020-04-16 various fixes from Static Code Analysis #SCA.  also need to beef up sqlSafe
    '*** 2020-10-16 considered adding a namespace, but this stops extensions from working.  Also to compile as a class library means extensions are not supported.
    '*** 2020-10-16 add LDAP support
    '*** 2020-11-12 updated checkLogonUser to use LDAP and also check userState and auditState fields if present.
    '*** 2021-05-05 added loadNonProdUser for non-prod DAST testing in Anonymous Authentication mode. Will load nonProdUser.xml as the pseudo LDAP user.
    '*** 2021-07-13 updated sqlSafe
    '*** https://stackoverflow.com/questions/5717359/how-to-add-description-to-functions-and-function-parameters
    '*** 2021-10-28 added an overload to CTypeOrFail
    '*** 2021-12-01 fixed bug in AUDITSTATE: verified and audit are ok, revoked and expired are not
    '*** 2021-12-07 setActivewMenuItemByValue added
    '*** 2022-04-22 Added more datatable routines. to/from base64 and to csv
    '*** 2022-05-31 added error result to checkLogonUser SQL version
    '*** 2022-10-13 added datatableToCrosstab extension method


#Region "...AUTHENTICATION AND LOGGING"
    Private Function loadNonProdUser(ByVal myPage As Page) As Boolean
        '*** 2021-05-05 attempt to load a pseudo LDAP profile from a local XML file. Expected fields are;
        '*** authuser, givenname, sn, mail, c  note that authuser is used to lookup the rest of the user profile in tblUserPermission
        '*** if an entry exists there. If not, then the admin page needs to work off the session vars (not getLDAP) to register the new user

        '*** example XML format
        '<?xml version="1.0" encoding="utf-8" ?>  
        '<nonProdUser>  
        '<AUTHUSER>SVC-rubix</AUTHUSER>
        '<GIVENNAME>Dast</GIVENNAME>
        '<SN>Rubix</SN>
        '<MAIL>dast.rubix@au.verizon.com</MAIL>
        '<C>AU</C>
        '</nonProdUser>

        If Not File.Exists(HttpContext.Current.Server.MapPath("nonProdUser.xml")) Then Return False

        Dim xmlreader As System.Xml.XmlTextReader = New System.Xml.XmlTextReader(HttpContext.Current.Server.MapPath("nonProdUser.xml"))

        Dim ds As New DataSet
        ds.ReadXml(xmlreader)

        If (ds.Tables.Count <> 0) Then
            '*** load the XML table contents into the session
            If ds.Tables(0).Rows.Count = 1 Then
                For Each myC As DataColumn In ds.Tables(0).Columns
                    myPage.Session(myC.ColumnName.ToUpper) = ds.Tables(0).Rows(0).Item(myC.ColumnName).ToString
                Next
            End If
            Return True
        End If

        Return False


    End Function

    ''' <summary>
    ''' Authenticates a request(LOGON_USER), supports use of IIS7 useRemoteWorkerProcess as the actual user identity at an ACL level
    ''' LOGON_USER is the AD authenticated user.  AUTH_USER and REMOTE_USER will be the application pool worker
    ''' populates session with LDAP details of the user
    ''' Supports nonProdUser.xml LDAP spoof profile for testing
    ''' Test err with TypeOf (err) Is System.Data.SqlClient.SqlException to determine if return=false due to db error
    ''' </summary>
    ''' <param name="myPage">the web page</param>
    ''' <param name="sqlConn">sql connection</param>
    ''' <param name="blRefresh">force a refresh of the authenticated user params in the session object</param>
    ''' <param name="blPathInfo">if true, will pull the pathinfo into a session(PATHINFO) object</param>
    ''' <param name="tblName">db table/query holding valid users</param>
    ''' <param name="err">returns exception code if failure due to database connection or other error</param>
    ''' <returns>True if user authenticates successfully.  Session(PATHINFO) holds any path info provided</returns>
    <Extension()>
    Public Function checkLogonUser(ByVal myPage As Page, ByRef sqlConn As SqlConnection, Optional ByVal blRefresh As Boolean = False, Optional ByVal blPathInfo As Boolean = False, Optional ByVal tblName As String = "tblUserPermission", Optional ByRef err As Exception = Nothing) As Boolean
        '*** 2018-04-27 supports use of IIS7 useRemoteWorkerProcess as the actual user identity at an ACL level.  We then check the AD authenticated user, who is
        '*** the LOGON_USER and this is the user we check is credentialled in our permitted user list.  This avoids need to ACL every user against the web directory
        '*** but does leverage AD authentication. It also allows self registration.
        '*** LOGON_USER is the AD authenticated user.  AUTH_USER and REMOTE_USER will be the app pool

        '*** 2019-04-29 overload now supports SQL server.  

        With myPage
            If blPathInfo Then
                If .Request.PathInfo.Length > 0 Then
                    'capture the pathInfo and add it to the Session object.  This is the easiest way to make it survive the 
                    'the redirect which we use to clean up the URL
                    '*** 2018-03-26 added URL decode to protect against XSS
                    .Session.Add("PATHINFO", HttpUtility.UrlDecode(.Request.PathInfo))
                    .Response.Redirect(.Request.ServerVariables("URL"))
                End If
            End If


            '1/ If session is still valid, exit true unless we are forcing a session vars refresh
            If (Not .Session("AUTHUSER") Is Nothing) And blRefresh = False Then
                '*** 2015-07-03 bug fix.  Users > 120 days inactive OR with no LastLoginUTC will return false
                If Not IsDate(.Session("LASTLOGINUTC")) Then Return False

                '*** users >120 days since last login will return false
                If (DateDiff(DateInterval.Day, .Session("LASTLOGINUTC"), Date.UtcNow)) > 120 Then Return False

                '*** 2015-09-17  If AccountLocked return false
                If CBool(.Session("ACCOUNTLOCKED")) Then Return False

                Return True
            End If

            '2/ if NTLM/AD fails to authenticate, terminate the app.  Don't want to use the test user in this scenario because its a security risk
            'any NTLM failure will lead to all users becoming the test user.
            If .User.Identity.IsAuthenticated = False Then
                '*** 2021-05-05 for non-production testing, check for a nonProdUser
                If Not loadNonProdUser(myPage) Then
                    '*** terminate the page
                    .Response.Write("<b=""red"">FATAL ERROR:  Active Directory user cannot be identified.</b>  Contact system administrator and report this error.")
                    .Response.End()
                    Return False
                End If
            End If


            '2a/ possible alt user
            '**** does User.Identity.Name match into altUser?
            If ConfigurationManager.AppSettings("altUser") Is Nothing Then
                '*** no altUser so go with LOGON_USER
                .Session("AUTHUSER") = .Request("LOGON_USER")
                '*** look for LOGON_USER in altUser, use Instr because regex will be confused by the \

                '*** new block will match full string prior to the colon
            ElseIf String.Equals(.Request("LOGON_USER"), Regex.Replace(ConfigurationManager.AppSettings("altUser").ToString, "([^\x5c]+\x5c\w+):(\w+)$", "$1"),
                             StringComparison.CurrentCultureIgnoreCase) = True Then

                '*** matches, so substitute the second group vID with the part after the colon. \x5C is a \ char
                .Session("AUTHUSER") = Regex.Replace(ConfigurationManager.AppSettings("altUser").ToString, "([^\x5c]+)\x5c(\w+):(\w+)$", "$1\$3")
            Else
                '*** does not match, use the LOGON_USER
                '*** 2021-05-05 only do this if LOGON_USER is not empty, to be compatible with loadNonProdUser
                If .Request("LOGON_USER").Length > 0 Then .Session("AUTHUSER") = .Request("LOGON_USER")
            End If

            '3/  refresh the system vars now that we have set a valid Session("AUTHUSER")
            ' Dim oConn As New SqlConnection(sConn)

            Try
                '*** 2020-04-16 SCA: tblName is not user generated, it is hardcoded in this app. remediated.
                Dim objCmd As New SqlCommand("SELECT * FROM [" & tblName & "] WHERE AUTHUSER=@p1", sqlConn)
                objCmd.Parameters.Add("@p1", SqlDbType.NVarChar).Value = .Session("AUTHUSER")
                sqlConn.Open()
                Dim objRead As SqlDataReader = objCmd.ExecuteReader(CommandBehavior.CloseConnection)

                If objRead.Read Then
                    Dim n As Integer
                    For n = 0 To objRead.FieldCount - 1
                        '*** note that all session vars are UPPER CASE to avoid case problems, even though in asp.net
                        '*** session keys are case insensitive
                        If objRead.Item(n) Is DBNull.Value Then
                            '*** map null to string.empty to help with regex tests later
                            .Session(objRead.GetName(n).ToUpper) = String.Empty
                        Else
                            .Session(objRead.GetName(n).ToUpper) = objRead.Item(n)
                        End If
                    Next
                    objRead.Close()
                End If

                '*** 2020-10-21 also pull in the LDAP fields
                Dim dtUser As DataTable = getLDAP(.Session("AUTHUSER"))
                If dtUser.Rows.Count = 1 Then
                    For Each myC As DataColumn In dtUser.Columns
                        .Session(myC.ColumnName.ToUpper) = dtUser.Rows(0).Item(myC.ColumnName).ToString
                    Next
                ElseIf Regex.IsMatch(.Session("AUTHUSER"), "user", RegexOptions.IgnoreCase) Then
                    '*** add support for test users, these must have an authuser name containing the word 'user'
                    .Session("SN") = .Session("AUTHUSER")
                    .Session("GIVENNAME") = "test"
                    .Session("MAIL") = "test@verizon.com"
                End If


                '*** 2015-09-17  If AccountLocked return false
                If CBool(.Session("ACCOUNTLOCKED")) Then Return False


                '*** 2015-05-11 For CPS108 compliance, we should deny users with >120 day access. To do this we'd simply test last login UTC
                '*** and return false at this step, not update the lastlogin value.
                '  .Trace.Warn("chckNTLM " & DateDiff(DateInterval.Day, .Session("LASTLOGINUTC"), Date.UtcNow))

                '*** 2015-07-03 bug fix.  Users > 120 days inactive OR with no LastLoginUTC will return false
                If Not IsDate(.Session("LASTLOGINUTC")) Then Return False

                If (DateDiff(DateInterval.Day, .Session("LASTLOGINUTC"), Date.UtcNow)) > 120 Then Return False
                '*** these session vars are not changed.  Main program code must look at the LASTLOGINUTC as a possible reason for the reject.
                '*** to reset the 120 day lockout, the admin must re-update a locked user.

                '*** 2015-05-11 update the lastlogin value
                '*** 2020-04-16 SCA: tblName is not user generated, it is hardcoded in this app. remediated.
                objCmd = New SqlCommand("UPDATE [" & tblName & "] SET LastLoginUTC=@p1 WHERE AUTHUSER=@p2", sqlConn)

                objCmd.Parameters.Add("@p1", SqlDbType.Date).Value = DateTime.UtcNow
                objCmd.Parameters.Add("@p2", SqlDbType.NVarChar).Value = .Session("AUTHUSER")
                sqlConn.Open()
                objCmd.ExecuteNonQuery()
                sqlConn.Close()

                '*** 2020-11-12 final checks, if these fields are present
                If Not .Session("USERSTATE") Is Nothing Then
                    If .Session("USERSTATE").ToString.ToUpper <> "ACTIVE" Then Return False
                End If

                If Not .Session("AUDITSTATE") Is Nothing Then
                    '*** 2021-12-01 verified and audit are ok, revoked and expired are not
                    If Regex.IsMatch(.Session("AUDITSTATE").ToString.ToUpper, "VERIFIED|AUDIT") = False Then Return False
                End If

                Return True
            Catch ex As Exception
                .Trace.Warn(ex.ToString)
                err = ex
                Return False
            Finally
                sqlConn.Dispose()
            End Try

        End With
    End Function
    ''' <summary>
    ''' Authenticates a request(LOGON_USER), supports use of IIS7 useRemoteWorkerProcess as the actual user identity at an ACL level
    ''' LOGON_USER is the AD authenticated user.  AUTH_USER and REMOTE_USER will be the application pool worker
    ''' populates session with LDAP details of the user
    ''' Supports nonProdUser.xml spoof LDAP profile for testing
    ''' </summary>
    ''' <param name="myPage">the web page</param>
    ''' <param name="oleConn">oledb connection</param>
    ''' <param name="blRefresh">force a refresh of the authenticated user params in the session object</param>
    ''' <param name="blPathInfo">if true, will pull the pathinfo into a session(PATHINFO) object, and then re-call the base URL as a redirect (hence postback=false)</param>
    ''' <param name="tblName">db table/query holding valid users</param>
    ''' <returns>True if user authenticates successfully.  Session(PATHINFO) holds any path info provided</returns>
    <Extension()>
    Public Function checkLogonUser(ByVal myPage As Page, ByRef oleConn As OleDb.OleDbConnection, Optional ByVal blRefresh As Boolean = False, Optional ByVal blPathInfo As Boolean = False, Optional ByVal tblName As String = "tblUserPermission") As Boolean
        '*** 2018-04-27 supports use of IIS7 useRemoteWorkerProcess as the actual user identity at an ACL level.  We then check the AD authenticated user, who is
        '*** the LOGON_USER and this is the user we check is credentialled in our permitted user list.  This avoids need to ACL every user against the web directory
        '*** but does leverage AD authentication. It also allows self registration.
        '*** LOGON_USER is the AD authenticated user.  AUTH_USER and REMOTE_USER will be the app pool
        With myPage
            If blPathInfo Then
                If .Request.PathInfo.Length > 0 Then
                    'capture the pathInfo and add it to the Session object.  This is the easiest way to make it survive the 
                    'the redirect which we use to clean up the URL
                    '*** 2018-03-26 added URL decode to protect against XSS
                    Dim temp As String = HttpUtility.UrlDecode(.Request.PathInfo)
                    .Session.Add("PATHINFO", HttpUtility.UrlDecode(.Request.PathInfo))
                    '*** 2020-04-16 SCA ensure URL is still local.  url.islocalurl is available in net 5 on
                    '*** however, the server-variable URL is always a partial local URL and is safe to redirect to

                    .Response.Redirect(.Request.ServerVariables("URL"))
                End If
            End If


            '1/ If session is still valid, exit true unless we are forcing a session vars refresh
            If (Not .Session("AUTHUSER") Is Nothing) And blRefresh = False Then
                '*** 2015-07-03 bug fix.  Users > 120 days inactive OR with no LastLoginUTC will return false
                If Not IsDate(.Session("LASTLOGINUTC")) Then Return False

                '*** users >120 days since last login will return false
                If (DateDiff(DateInterval.Day, .Session("LASTLOGINUTC"), Date.UtcNow)) > 120 Then Return False

                '*** 2015-09-17  If AccountLocked return false
                If CBool(.Session("ACCOUNTLOCKED")) Then Return False

                Return True
            End If

            '2/ if NTLM/AD fails to authenticate, terminate the app.  Don't want to use the test user in this scenario because its a security risk
            'any NTLM failure will lead to all users becoming the test user.
            If .User.Identity.IsAuthenticated = False Then
                '*** 2021-05-05 for non-production testing, check for a nonProdUser
                If Not loadNonProdUser(myPage) Then
                    '*** terminate the page
                    .Response.Write("<b=""red"">FATAL ERROR:  Active Directory user cannot be identified.</b>  Contact system administrator and report this error.")
                    .Response.End()
                    Return False
                End If
            End If


            '2a/ possible alt user
            '**** does User.Identity.Name match into altUser?
            If ConfigurationManager.AppSettings("altUser") Is Nothing Then
                '*** no altUser so go with LOGON_USER
                .Session("AUTHUSER") = .Request("LOGON_USER")
                '*** look for LOGON_USER in altUser, use Instr because regex will be confused by the \

                '*** new block will match full string prior to the colon
            ElseIf String.Equals(.Request("LOGON_USER"), Regex.Replace(ConfigurationManager.AppSettings("altUser").ToString, "([^\x5c]+\x5c\w+):(\w+)$", "$1"),
                             StringComparison.CurrentCultureIgnoreCase) = True Then

                '*** matches, so substitute the second group vID with the part after the colon. \x5C is a \ char
                .Session("AUTHUSER") = Regex.Replace(ConfigurationManager.AppSettings("altUser").ToString, "([^\x5c]+)\x5c(\w+):(\w+)$", "$1\$3")
            Else
                '*** does not match, use the LOGON_USER
                '*** 2021-05-05 only do this if LOGON_USER is not empty, to be compatible with loadNonProdUser
                If .Request("LOGON_USER").Length > 0 Then .Session("AUTHUSER") = .Request("LOGON_USER")
            End If

            '3/  refresh the system vars now that we have set a valid Session("AUTHUSER")
            'Dim oConn As New OleDb.OleDbConnection(sConn)

            Try
                '*** 2020-04-16 SCA: tblName is not user generated, it is hardcoded in this app. remediated.
                Dim objCmd As New OleDb.OleDbCommand("SELECT * FROM " & tblName & " WHERE AUTHUSER=@p1", oleConn)
                objCmd.Parameters.Add("@p1", OleDb.OleDbType.VarChar).Value = .Session("AUTHUSER")
                oleConn.Open()
                Dim objRead As OleDb.OleDbDataReader = objCmd.ExecuteReader(CommandBehavior.CloseConnection)

                If objRead.Read Then

                    Dim n As Integer
                    For n = 0 To objRead.FieldCount - 1
                        '*** note that all session vars are UPPER CASE to avoid case problems, even though in asp.net
                        '*** session keys are case insensitive
                        If objRead.Item(n) Is DBNull.Value Then
                            '*** map null to string.empty to help with regex tests later
                            .Session(objRead.GetName(n).ToUpper) = String.Empty
                        Else
                            .Session(objRead.GetName(n).ToUpper) = objRead.Item(n)
                        End If
                    Next
                    objRead.Close()
                End If

                '*** 2020-10-21 also pull in the LDAP fields
                Dim dtUser As DataTable = getLDAP(.Session("AUTHUSER"))
                If dtUser.Rows.Count = 1 Then
                    For Each myC As DataColumn In dtUser.Columns
                        .Session(myC.ColumnName.ToUpper) = dtUser.Rows(0).Item(myC.ColumnName).ToString
                    Next
                ElseIf Regex.IsMatch(.Session("AUTHUSER"), "user", RegexOptions.IgnoreCase) Then
                    '*** add support for test users, these must have an authuser name containing the word 'user'
                    .Session("SN") = .Session("AUTHUSER")
                    .Session("GIVENNAME") = "test"
                    .Session("MAIL") = "test@verizon.com"
                End If


                '*** 2015-09-17  If AccountLocked return false
                '*** 2020-10-20 this field is deprecated, will not cause an error
                If .Session("ACCOUNTLOCKED") Then Return False

                '*** 2015-05-11 For CPS108 compliance, we should deny users with >120 day access. To do this we'd simply test last login UTC
                '*** and return false at this step, not update the lastlogin value.
                '  .Trace.Warn("chckNTLM " & DateDiff(DateInterval.Day, .Session("LASTLOGINUTC"), Date.UtcNow))

                '*** 2015-07-03 bug fix.  Users > 120 days inactive OR with no LastLoginUTC will return false
                If Not IsDate(.Session("LASTLOGINUTC")) Then Return False

                If (DateDiff(DateInterval.Day, .Session("LASTLOGINUTC"), Date.UtcNow)) > 120 Then Return False
                '*** these session vars are not changed.  Main program code must look at the LASTLOGINUTC as a possible reason for the reject.
                '*** to reset the 120 day lockout, the admin must re-update a locked user.

                '*** 2015-05-11 update the lastlogin value
                '*** 2020-04-16 SCA: tblName is not user generated, it is hardcoded in this app. remediated.
                objCmd = New OleDb.OleDbCommand("Update " & tblName & " SET LastLoginUTC=@p1 WHERE AUTHUSER=@p2", oleConn)

                objCmd.Parameters.Add("@p1", OleDb.OleDbType.Date).Value = DateTime.UtcNow
                objCmd.Parameters.Add("@p2", OleDb.OleDbType.VarChar).Value = .Session("AUTHUSER")
                oleConn.Open()
                objCmd.ExecuteNonQuery()
                oleConn.Close()

                '*** 2020-11-12 final checks, if these fields are present
                If Not .Session("USERSTATE") Is Nothing Then
                    If .Session("USERSTATE").ToString.ToUpper <> "ACTIVE" Then Return False
                End If

                If Not .Session("AUDITSTATE") Is Nothing Then
                    '*** 2021-12-01 verified and audit are ok, revoked and expired are not
                    If Regex.IsMatch(.Session("AUDITSTATE").ToString.ToUpper, "VERIFIED|AUDIT") = False Then Return False
                End If

                '*** this is the only return true exit point.
                Return True

            Catch ex As Exception
                .Trace.Warn(ex.ToString)
                Return False
            Finally
                oleConn.Dispose()
            End Try

        End With
    End Function

    Public Function writeAudit(ByVal buffer As String, ByVal sNTID As String) As String
        '*** write to audit.txt in the files folder
        '*** needs reference imports system.IO
        'http://www.builderau.com.au/program/windows/soa/Reading-and-writing-text-files-with-VB-NET/0,339024644,320267367,00.htm

        Dim oWrite As StreamWriter
        Try
            oWrite = File.AppendText(System.Configuration.ConfigurationManager.AppSettings("strUserFiles") & "\audit.txt")
            buffer = String.Concat(Format(DateTime.UtcNow, "u"), vbTab, sNTID, vbTab, buffer)
            oWrite.WriteLine(buffer)
            'oWrite.WriteLine("{0,10:dd MMMM}{0,10:hh:mm tt}{1,25:C}", Now(), 13455.33)
            oWrite.Close()
            Return True
        Catch ex As Exception
            Return ex.ToString
        End Try
    End Function
#End Region


#Region "...DATATABLE RELATED..."
    ''' <summary>
    ''' will generate a crosstab table from the input data dt.  Automatically deals with types and null values
    ''' </summary>
    ''' <param name="dt">input datatable</param>
    ''' <param name="columnHeading">columnHeading values are crosstabbed</param>
    ''' <param name="valueField">the desired output value. SUM is supported in this version</param>
    ''' <param name="rowHeading">string array of rowheading values</param>
    ''' <param name="sOperation">sum|max|min|avg</param>
    ''' <returns>a crosstab dataset</returns>
    <Extension()>
    Function datatableToCrosstab(dt As DataTable, columnHeading As String, valueField As String, rowHeading() As String, Optional sOperation As String = "sum") As DataTable
        'transforms data to a cross tab.  assume valuefield will be SUM for now

        '2022-10-05 need to cope with null entries for one/more of the rowHeadings

        '1/ select distinct columnHeading and sort ASC. Have to use a dataview to effect the sorting
        Dim dtColumnsView As DataView = dt.DefaultView
        dtColumnsView.Sort = columnHeading
        Dim dtColumns As DataTable = dtColumnsView.ToTable(True, columnHeading)


        '2/ select distinct rowHeading based off param array
        Dim dtRows As DataTable = (dt.DefaultView).ToTable(True, rowHeading)

        '3/ build the crosstab output table
        Dim dtCrosstab As New DataTable
        '*** add the rowHeadings as strings, even though they may in fact be typed differently...
        For Each colName As String In rowHeading
            '** find source column, copy to dtCrosstab.  There's no copy/clone function so create with samename and type
            'note: datatable merge can be used to merge one table into another
            Dim myC As New DataColumn(colName, dt.Columns(colName).DataType)
            dtCrosstab.Columns.Add(myC)

        Next

        '*** now add output columns, yeah its confusing, we have rows of columns...
        For Each col As DataRow In dtColumns.Rows
            '** add a column of the columnHeading datatype but named as one of the rows of columns :-)
            '** note that col(columnHeading) may be null if the underlying data is a left join and has null outputs
            If col(columnHeading) & String.Empty = String.Empty Then
                '*** deal with null
                ' Dim myC As New DataColumn("<>", dt.Columns(columnHeading).DataType)
                ' dtCrosstab.Columns.Add(myC)
                ' Trace.Warn("col " & myC.ColumnName)
            Else
                Dim myC As New DataColumn(col(columnHeading), dt.Columns(columnHeading).DataType)
                dtCrosstab.Columns.Add(myC)
                'Trace.Warn("col " & myC.ColumnName)
            End If


        Next

        'run sum compute on the data to calculate the value and build the return dataset
        '*** add a row of data
        'Trace.Warn("step3 complete")


        '4/ run the compute to populate
        For Each myR In dtRows.Rows

            Dim newR As DataRow = dtCrosstab.NewRow
            Dim sbFilter As New StringBuilder
            '*** populate the rowHEadings
            For Each colName As String In rowHeading
                newR(colName) = myR(colName)
                sbFilter.Append(colName)

                '*** refactored
                '2022-10-05 bug fix, detect null values and use isNull rather than =
                If (myR(colName)).ToString.Trim = String.Empty Then
                    sbFilter.Append(" IS NULL")
                ElseIf newR(colName).GetType = GetType(String) Then
                    sbFilter.Append("='")
                    sbFilter.Append(myR(colName))
                    sbFilter.Append("'")
                Else
                    sbFilter.Append("=")
                    sbFilter.Append(myR(colName))
                End If

                sbFilter.Append(" AND ")

            Next
            Dim sbFilterLen As Long = sbFilter.Length

            '*** capture sbFilter length at this point so we can keep varying it
            '** and inner loop for the values, using compute
            For Each col As DataRow In dtColumns.Rows

                '*** need to cast to string, else it uses col(columnHeading) as a numeric index
                sbFilter.Append(columnHeading)
                If col(columnHeading).ToString.Trim = String.Empty Then
                    sbFilter.Append(" IS NULL")

                ElseIf newR(col(columnHeading).ToString).GetType = GetType(String) Then
                    sbFilter.Append("='")
                    sbFilter.Append(col(columnHeading))
                    sbFilter.Append("'")
                Else
                    sbFilter.Append("=")
                    sbFilter.Append(col(columnHeading))
                End If


                'Trace.Warn("sbFilter=" & sbFilter.ToString)

                '** not sure why we need this test...
                If Not col(columnHeading).ToString.Trim = String.Empty Then
                    '*** only compute if we have a valid target column
                    newR(col(columnHeading).ToString) = dt.Compute(sOperation & "(" & valueField & ")", sbFilter.ToString)
                End If


                'filter is where rh1,rh2 etc = their values and columnheading_field=col(columnheading) 
                'but its made more complex because you need to ensure types are properly dealt with
                'e.g. if f1 is string, f2 double then f1='this' AND f2=99

                '*** compute probably supports max, min, sum, avg. we could accept a defining param and test and throw and error if bad

                sbFilter.Remove(sbFilterLen, sbFilter.Length - sbFilterLen)

            Next
            dtCrosstab.Rows.Add(newR)
        Next
        Return dtCrosstab

    End Function




    ''' <summary>
    ''' pulls a CSV format file conforming to RFC8140 into a datatable. First row is deemed a header.
    ''' </summary>
    ''' <param name="uFile">fileupload object</param>
    ''' <param name="dtName">result datatable name</param>
    ''' <returns>datatable with all fields as strings. further process this with CTypeOrFail</returns>
    <Extension()>
    Function fileToDatatable(uFile As FileUpload, dtName As String) As DataTable
        '*** 2019-01-21.  will pull in a CSV format file conforming to RFC8140 and populate a datatable with it.
        Dim sR As StreamReader = New StreamReader(uFile.FileContent)
        Dim afile As FileIO.TextFieldParser = New FileIO.TextFieldParser(New StringReader(sR.ReadToEnd().ToString()))
        sR.Dispose()

        Dim CurrentRecord As String() ' this array will hold each line of data
        afile.TextFieldType = FileIO.FieldType.Delimited
        afile.Delimiters = New String() {","}
        afile.HasFieldsEnclosedInQuotes = True

        Dim dtI As New DataTable(dtName)
        Dim r As Long = 0
        Dim c As Integer = 0
        Dim dr As DataRow = Nothing

        Do While Not afile.EndOfData
            Try
                CurrentRecord = afile.ReadFields
                c = 0
                If r > 0 Then
                    dr = dtI.NewRow
                End If

                For Each s As String In CurrentRecord
                    If r = 0 Then
                        dtI.Columns.Add(s)
                    Else
                        '*** treat as data.  Special case for iso-dates containing zeros, strip this off
                        dr.Item(c) = Regex.Replace(s, " 00:00:00", String.Empty)
                        c += 1
                    End If
                Next
                If r > 0 Then dtI.Rows.Add(dr)
                r += 1
            Catch ex As FileIO.MalformedLineException
                'ERROR the CSV file does not conform to RFC8140
                'maybe we should let this error bubble up?
                '*** using Throw will bubble up the exception and also preserve the stack trace where it originated
                Throw
                'Return Nothing
                Exit Function
            End Try
        Loop
        afile.Dispose()
        Return dtI

    End Function
    ''' <summary>
    ''' overload, accepts an IO stream
    ''' </summary>
    ''' <param name="fc">IO stream</param>
    ''' <param name="dtName">returned datatable name</param>
    ''' <returns>datatable with all fields as strings</returns>

    <Extension()>
    Function fileToDatatable(ByVal fc As System.IO.Stream, dtName As String) As DataTable
        '*** 2021-03-10 overload
        Dim sR As StreamReader = New StreamReader(fc)
        Dim afile As FileIO.TextFieldParser = New FileIO.TextFieldParser(New StringReader(sR.ReadToEnd().ToString()))
        sR.Dispose()

        Dim CurrentRecord As String() ' this array will hold each line of data
        afile.TextFieldType = FileIO.FieldType.Delimited
        afile.Delimiters = New String() {","}
        afile.HasFieldsEnclosedInQuotes = True

        Dim dtI As New DataTable(dtName)
        Dim r As Long = 0
        Dim c As Integer = 0
        Dim dr As DataRow = Nothing

        Do While Not afile.EndOfData
            Try
                CurrentRecord = afile.ReadFields
                c = 0
                If r > 0 Then
                    dr = dtI.NewRow
                End If

                For Each s As String In CurrentRecord
                    If r = 0 Then
                        dtI.Columns.Add(s)
                    Else
                        '*** treat as data.  Special case for iso-dates containing zeros, strip this off
                        dr.Item(c) = Regex.Replace(s, " 00:00:00", String.Empty)
                        c += 1
                    End If
                Next
                If r > 0 Then dtI.Rows.Add(dr)
                r += 1
            Catch ex As FileIO.MalformedLineException
                'ERROR the CSV file does not conform to RFC8140
                'maybe we should let this error bubble up?
                '*** using Throw will bubble up the exception and also preserve the stack trace where it originated
                Throw
                'Return Nothing
                Exit Function
            End Try
        Loop
        afile.Dispose()
        Return dtI

    End Function
    ''' <summary>
    ''' coerces to type specified in tCode or returns null by default. example: cTypeOrNull("23",typeCode.Double)
    ''' </summary>
    ''' <param name="x">input object holding value</param>
    ''' <param name="tCode">typecode to co-erce to</param>
    ''' <param name="errVal">oject to return if error</param>
    ''' <returns>type specified, or optional errVal or null by default</returns>

    Function CTypeOrFail(x As Object, tCode As TypeCode, Optional errVal As Object = Nothing) As Object
        '*** coerces to type specified in tCode or returns null by default, else you can specify a return value, e.g. string.empty
        '*** example call  cTypeOrNull("23",typeCode.Double)
        Try
            Return Convert.ChangeType(x, tCode)
        Catch
            Return errVal
        End Try

    End Function
    ''' <summary>
    ''' overload
    ''' </summary>
    ''' <param name="x">input object holding value</param>
    ''' <param name="t">type to co-erce to</param>
    ''' <param name="errVal">oject to return if error</param>
    ''' <returns>type specified, or optional errVal or null by default</returns>

    Function CTypeOrFail(x As Object, t As Type, Optional errVal As Object = Nothing) As Object
        '*** coerces to type specified in tCode or returns null by default, else you can specify a return value, e.g. string.empty
        '*** example call  cTypeOrNull("23",typeCode.Double)
        Try
            Return Convert.ChangeType(x, t)
        Catch
            Return errVal
        End Try

    End Function




    ''' <summary>
    ''' searches an object (page, gridview) for controls with an id of fld_field1 matching these into a dataRow and then binding the dataRow to the control
    ''' controls can have additional optional attributes;
    ''' DFS="{0:c}" on TextBox controls; this formats the presentation
    ''' bind="text|value [nobind] [legacy] [blank]" where;
    '''      text|value signifies how to bind to the dropdownlist options to the database
    '''      optional nobind signifies this sub is to ignore the control (useful if other code sets value and you still want to unbind)
    '''      optional legacy will add an extra dropdown option and select it to support legacy data
    '''      optional blank will add a blank entry to end of list
    ''' CheckBox controls are rendered to checked or not based on boolean value
    ''' text and literals are HTMLencoded to protect against XSS attacks.
    ''' IMPORTANT findbyValue is case sensitive
    ''' </summary>
    ''' <param name="myRow">dataset datarow</param>
    ''' <param name="lookHere">look for controls here, can be page, gridview row, datagrid row etc</param>
    ''' <param name="sPrefix">control ID prefix for corresponding dataset field, e.g. field1 has a control id=fld_field1</param>
    <Extension()>
    Sub doBindDataRow(ByRef myRow As DataRow, ByVal lookHere As Object, Optional ByVal sPrefix As String = "fld_")
        '*** this code takes a data row, and searches the lookHere object (page or datagriditem) for controls with an id of fld_field1 (this prefix can be overidden) etc
        '*** where field1 is a dataset field
        '*** additional attribute you can put on the control are;
        '*** optional DFS="{0:c}" on TextBox controls; this formats the presentation
        '*** 2009-12-14 attribute bind usage; bind="text|value [nobind] [legacy] [blank]" where;
        '*** text|value signifies how to bind to the dropdownlist options to the database
        '*** optional nobind signifies this sub is to ignore the control (useful if other code sets value and you still want to unbind)
        '*** optional legacy will add an extra dropdown option and select it to support legacy data
        '*** optional blank will add a blank entry to end of list
        '*** CheckBox controls are rendered to checked or not based on boolean value
        '*** IMPORTANT findbyValue is case sensitive
        '*** 2018-03-21 text and literals are HTMLencoded to protect against XSS attacks.

        Dim myColumn As DataColumn

        '*** find parent DataTable and its schema
        For Each myColumn In myRow.Table.Columns

            Try
                '*** pick up the data item, don't force type conversion yet
                Dim s As Object = myRow.Item(myColumn.ColumnName)
                '*** now lets populate the form. First find the control
                Dim myControl As Object = lookHere.FindControl(sPrefix & myColumn.ColumnName)
                '*** 2009-12-21 some controls, such as literals have no attributes and will cause an error if you try to access these
                '*** at this point, so wait until we are working with the DDlist
                If TypeOf (myControl) Is TextBox Then
                    Dim myTextBox As TextBox = myControl
                    '*** don't force type conversion yet, unless s is NULL
                    If s Is DBNull.Value Then s = String.Empty

                    '*** look for optional DFS attribute which will contain a formatting string
                    If myTextBox.Attributes("DFS") Is Nothing Then
                        '*** if no format string present, then convert to a string

                        myTextBox.Text = HttpUtility.HtmlEncode(s.ToString)
                    ElseIf myTextBox.Attributes("DFS") = "percent" Then
                        '*** special setting to convert a text field to a percent figure
                        If IsNumeric(s) Then
                            If s < 2 Then myTextBox.Text = FormatPercent(s, 2, TriState.True)
                        Else
                            myTextBox.Text = HttpUtility.HtmlEncode(s.ToString)
                        End If
                    Else
                        '*** the formatting will convert to string, but this formatting only works if the object is still
                        '*** intact e.g. a date, time, double etc, hence we did not force to a string earlier
                        myTextBox.Text = HttpUtility.HtmlEncode(String.Format(myTextBox.Attributes("DFS"), s))
                    End If

                    '*** for checkboxes, we only need worry about the boolean value
                ElseIf TypeOf (myControl) Is CheckBox Then
                    Dim myCheckbox As CheckBox = myControl
                    myCheckbox.Checked = CBool(s)

                ElseIf TypeOf (myControl) Is DropDownList Then
                    '*** For dropdowns, list items must be bound prior.  We are looking to select a text or value
                    '*** entry as found in our target datarow field
                    '*** switch options are bind="text|value [nobind] [legacy] [blank]"
                    '*** default is text if bind attrib not present
                    If Not Regex.IsMatch(myControl.attributes("bind") & String.Empty, "nobind", RegexOptions.IgnoreCase) Then
                        Dim myDropdown As DropDownList = myControl
                        Dim oItem As ListItem
                        Dim blLegacy As Boolean = Regex.IsMatch(myDropdown.Attributes("bind") & String.Empty, "legacy", RegexOptions.IgnoreCase)
                        Dim blBlank As Boolean = Regex.IsMatch(myDropdown.Attributes("bind") & String.Empty, "blank", RegexOptions.IgnoreCase)
                        If s Is DBNull.Value Then s = String.Empty '*** we can't bind dbNULL do convert to string.empty
                        '*** 2009-12-14 some changes to the bind parameter and legacy parameter
                        If Regex.IsMatch(myDropdown.Attributes("bind") & String.Empty, "value", RegexOptions.IgnoreCase) Then
                            '*** find by value, but first check wether we are supporting legacy values (i.e. those not bound in the list)
                            If myDropdown.Items.FindByValue(CType(s, String)) Is Nothing And blLegacy Then
                                oItem = New ListItem(HttpUtility.HtmlEncode(s.ToString), HttpUtility.HtmlEncode(s.ToString))
                                myDropdown.Items.Add(oItem) '*** add a legacy item
                                '*** now also add a blank if required (and hasn't just been added as a legacy item)
                            Else
                                oItem = myDropdown.Items.FindByValue(CType(s, String))
                            End If
                            myDropdown.SelectedIndex = myDropdown.Items.IndexOf(oItem)
                        Else
                            '*** default is to find by text
                            If myDropdown.Items.FindByText(CType(s, String)) Is Nothing And blLegacy Then
                                oItem = New ListItem(CType(s, String), CType(s, String))
                                myDropdown.Items.Add(oItem)
                            Else
                                oItem = myDropdown.Items.FindByText(CType(s, String))
                            End If
                            myDropdown.SelectedIndex = myDropdown.Items.IndexOf(oItem)
                        End If  '*** value test

                        '*** now add a blank if required, and select it if required
                        If blBlank Then
                            '*** add a blank if one does not already exist
                            If CBool(myDropdown.Items.FindByValue(String.Empty) Is Nothing) Then myDropdown.Items.Add(New ListItem(String.Empty, String.Empty))
                            '*** If we do not have a valid oItem from before, then select this blank value
                            If oItem Is Nothing Then
                                oItem = myDropdown.Items.FindByValue(String.Empty)
                                myDropdown.SelectedIndex = myDropdown.Items.IndexOf(oItem)
                            End If
                        End If '*** blank 

                    End If  '*** end nobind test

                ElseIf TypeOf (myControl) Is Literal Then
                    Dim myLiteral As Literal = myControl
                    If s Is DBNull.Value Then
                        myLiteral.Text = String.Empty
                    Else
                        myLiteral.Text = HttpUtility.HtmlEncode(s.ToString)
                    End If

                    '*** end of control types
                End If


            Catch
            End Try
        Next myColumn
    End Sub
    ''' <summary>
    ''' searches an object (page, gridview) for controls with an id of fld_field1 matching these into a dataRow and then unbinding the page data back to the dataRow
    ''' controls can optional attribute bind="nounbind" which will skip unbinding that control.  Useful if other logic is to drive the control
    ''' Do not use with boundcontrol types such as asp:checkboxfield as these will not work correctly
    ''' Dates are a problem, if you format as one locale but server/db has another you will hit problems
    ''' XSS: ensure that validaterequest=true (the page default) 
    ''' </summary>
    ''' <param name="myRow">target database datarow to receive data</param>
    ''' <param name="lookHere">page or gridviewrow holding controls</param>
    ''' <param name="sPrefix">field prefix e.g. if database is field1, id=fld_field1</param>
    <Extension()>
    Sub doUnbindDataRow(ByRef myRow As DataRow, ByVal lookHere As Object, Optional ByVal sPrefix As String = "fld_")
        '*** based on the db-datarow column names, looks for fields fld_field1 etc on the page
        '*** lookHere could be the page object or a datagriditem
        '*** so whilst original page may have been populated with one query, its possible to bind
        '*** page control values back to a different query
        '*** NOTE do not rebind the controls until AFTER you have called this sub
        '*** NOTE: Dates are a problem.  If you force them to display as MM/DD/YYYY, you have a problem writing
        '*** them back to the db, as its locale might expect DD/MM/YYYY
        '*** also, if you don't want createDates being trunkated back in the db, need to make them display readonly or disabled
        '*** 2010-03-30 optional attribute bind="nounbind" meaning that we won't unbind the data back to the database the
        '*** reason for this feature is that sometimes we want to save a record, but have say a status dropdown written to db by other logic

        '*** 2015-05-05 IMPORTANT: do not use highlevel grid controls such as <asp:checkboxfield> in conjunction with <asp:templatefield> because the first
        '*** will unbind the control value and stop the templatefield from working.  templatefields also don't enumerate to useful IDs

        '*** 2018-03-21 to protect against ingesting data that is potentially a cross site script attack XSS, ensure that validaterequest=true (the page default)
        '*** there is no benefit to HTMLdecoding here because the page should trap potentially unsafe text strings
        '*** https://www.apexhost.com.au/knowledgebase.php?action=displayarticle&id=66

        Dim myColumn As DataColumn

        '*** REMEMBER that reserved names such as Currency cause problems for the Updatebuilder

        '*** find parent DataTable and its schema
        For Each myColumn In myRow.Table.Columns
            Try
                '*** pick up the data item, don't force type conversion yet
                Dim s As Object = myRow.Item(myColumn.ColumnName)
                '*** now lets populate the datarow from the form. First find the control
                Dim myControl As Object = lookHere.FindControl(sPrefix & myColumn.ColumnName)
                If myControl Is Nothing Then
                    '*** do nothing, control cannot be found
                ElseIf Regex.IsMatch(myControl.attributes("bind") & String.Empty, "nounbind", RegexOptions.IgnoreCase) Then
                    '*** do nothing, user has disabled unbinding of the control
                ElseIf Not myControl.Enabled Then
                    '*** do nothing - enabled is a property found on ALL controls
                    '*** else what type of control is it?
                ElseIf TypeOf (myControl) Is TextBox Then
                    Dim myTextBox As TextBox = myControl
                    '*** handle zero length strings - allowDBNull
                    If myTextBox.ReadOnly Then
                        '*** do nothing - this property is specific to textboxes
                    ElseIf myColumn.AllowDBNull And myTextBox.Text = "" Then
                        '*** write a null
                        myRow.Item(myColumn.ColumnName) = DBNull.Value
                    ElseIf myColumn.DataType.ToString = "System.Int32" Then
                        '*** convert numeric types first
                        myRow.Item(myColumn.ColumnName) = CLng(myTextBox.Text)
                    ElseIf myColumn.DataType.ToString = "System.DateTime" Then
                        myRow.Item(myColumn.ColumnName) = CDate(myTextBox.Text)
                    ElseIf myColumn.DataType.ToString = "System.Double" Then
                        '*** check to see if we need to handle a percentage
                        If Regex.IsMatch(myTextBox.Text, "^[-\d\.]+%$") Then
                            myRow.Item(myColumn.ColumnName) = CDbl(myTextBox.Text.ToString.Replace("%", String.Empty)) / 100
                        Else
                            myRow.Item(myColumn.ColumnName) = CDbl(myTextBox.Text)
                        End If

                    Else
                        '*** write any text, including zero len
                        '*** 2014-03-20 modified this to trim the spaces first
                        myRow.Item(myColumn.ColumnName) = myTextBox.Text.Trim
                    End If

                    '*** for checkboxes, we only need worry about the boolean value
                ElseIf TypeOf (myControl) Is CheckBox Then
                    Dim myCheckbox As CheckBox = myControl
                    myRow.Item(myColumn.ColumnName) = myCheckbox.Checked
                ElseIf TypeOf (myControl) Is DropDownList Then
                    '*** For dropdowns, we are looking for selecteditemValue only
                    Dim myDropdown As DropDownList = myControl
                    If myColumn.DataType.ToString() = "System.Boolean" Then
                        myRow.Item(myColumn.ColumnName) = CBool(myDropdown.SelectedValue)
                    ElseIf myColumn.AllowDBNull And myDropdown.SelectedValue = String.Empty Then
                        '*** write a null if we cannot have zero len strings
                        myRow.Item(myColumn.ColumnName) = DBNull.Value
                    Else
                        myRow.Item(myColumn.ColumnName) = myDropdown.SelectedValue
                    End If

                    '*** end control type tests
                End If

            Catch

            Finally
            End Try

        Next myColumn
    End Sub

    <Extension()>
    Sub exportRFC4180table(ByVal myPage As Page, ByVal dTbl As DataTable, Optional ByVal myFilename As String = "test.csv", Optional ByVal noSLYK As Boolean = False)
        '*** exports a datatable to XL. Originally this used vbTab chars to separate the variables, however if you do this then
        '*** XL throws an annoying error "content does not match the description" i.e. the thing is full of tabs but the filename is .xls or .csv
        '*** to work around it use commas as the separator, and use .csv as the filename.  Then it opens straight in XL with no fuss.
        '*** http://tools.ietf.org/html/rfc4180
        '*** WELL ALMOST.  you have to escape commas by enclosing in quotes.  I am not bothering to escape quotes.
        '*** GOTCHA. ID as the first column header will cause a problem as XL thinks the file is an SYLK file, remove this from your datatable

        '*** 2016-06-30 updated the tool to delete first col if noSLYK is true
        Try
            With myPage
                If noSLYK Then
                    dTbl.Columns.RemoveAt(0)
                End If

                .Trace.IsEnabled = False
                Dim attachment As String = "attachment; filename=" & myFilename
                .Response.ClearContent()
                .Response.AddHeader("content-disposition", attachment)
                .Response.ContentType = "application/vnd.ms-excel"
                Dim tb As String = String.Empty
                For Each dtcol As DataColumn In dTbl.Columns

                    .Response.Write(tb & dtcol.ColumnName)
                    tb = ","
                Next

                .Response.Write(vbCrLf)
                For Each dr As DataRow In dTbl.Rows

                    tb = ""
                    Dim j As Integer
                    For j = 0 To dTbl.Columns.Count - 1

                        If Regex.IsMatch(dr(j).ToString, ",") Then
                            'RFC4180 requires any field containing a comma to be enclosed in quotes at each end of field value
                            .Response.Write(tb & """" & dr(j).ToString & """")
                        Else
                            .Response.Write(tb & dr(j).ToString)
                        End If

                        tb = ","
                    Next
                    .Response.Write(vbCrLf)
                Next
                'https://stackoverflow.com/questions/10603553/response-end-vs-httpcontext-current-applicationinstance-completerequest
                'https://stackoverflow.com/questions/10603553/response-end-vs-httpcontext-current-applicationinstance-completerequest
                'https://weblog.west-wind.com/posts/2008/May/26/Ending-a-Response-without-ResponseEnd-Exceptions
                'response.end is considered harmful because it aborts a thread,  it cannot be error trapped

                '*** 2019-03-13 tested and works instead of Response.End()
                .Response.Flush()
                .Response.SuppressContent = True
                HttpContext.Current.ApplicationInstance.CompleteRequest()

            End With
        Catch ex As Exception
            '*** report errors only if trace is enabled.  in production you will always get a thread abort error and we don't want this in the report
            If myPage.Trace.IsEnabled Then myPage.Response.Write(ex.ToString)

        End Try
    End Sub
    <Extension()>
    Sub exportRFC4180table(ByVal myPage As Page, ByVal dTbl As DataTable, Optional ByVal myFilename As String = "data.csv", Optional ByVal blISOdate As Boolean = True, Optional ByVal blSYLK As Boolean = False)
        '*** overload
        '*** modified 2016-02-22 with code to force dates to ISO format
        '*** modified 2017-11-28 to optionally remove first column from table to fix SYLK issues
        '*** modified 2020-11-09 to force XL to accept ISOdates as a text string, which stops it recasting them in its own locale

        '*** exports a datatable to XL. Originally this used vbTab chars to separate the variables, however if you do this then
        '*** XL throws an annoying error "content does not match the description" i.e. the thing is full of tabs but the filename is .xls or .csv
        '*** to work around it use commas as the separator, and use .csv as the filename.  Then it opens straight in XL with no fuss.
        '*** http://tools.ietf.org/html/rfc4180
        '*** WELL ALMOST.  you have to escape commas by enclosing in quotes.  I am not bothering to escape quotes.
        '*** GOTCHA. ID as the first column header will cause a problem as XL thinks the file is an SYLK file, remove this from your datatable

        Try
            With myPage
                If blSYLK Then
                    dTbl.Columns.RemoveAt(0)
                End If

                .Trace.IsEnabled = False
                Dim attachment As String = "attachment; filename=" & myFilename
                .Response.ClearContent()
                .Response.AddHeader("content-disposition", attachment)
                .Response.ContentType = "application/vnd.ms-excel"
                Dim tb As String = String.Empty
                For Each dtcol As DataColumn In dTbl.Columns

                    .Response.Write(tb & dtcol.ColumnName)
                    tb = ","
                Next

                .Response.Write(vbCrLf)
                For Each dr As DataRow In dTbl.Rows

                    tb = ""
                    Dim j As Integer
                    For j = 0 To dTbl.Columns.Count - 1

                        If Regex.IsMatch(dr(j).ToString, ",") Then
                            'RFC4180 requires any field containing a comma to be enclosed in quotes at each end of field value
                            .Response.Write(tb & """" & dr(j).ToString & """")
                        ElseIf IsDate(dr(j).ToString) And Not IsNumeric(dr(j).ToString) Then
                            '*** 2020-11-09 added apostrophe in front of date to force XL to keep at text.  If you enclose with quotes, XL will still 
                            '*** convert Text dates to its locale date format
                            '*** https://stackoverflow.com/questions/165042/stop-excel-from-automatically-converting-certain-text-values-to-dates
                            '*** the solution is "=""2008-10-03"""
                            .Response.Write(tb & "=""" & Format(CDate(dr(j).ToString), "yyyy-MM-dd") & """")
                        Else
                            .Response.Write(tb & dr(j).ToString)
                        End If

                        tb = ","
                    Next
                    .Response.Write(vbCrLf)
                Next
                'https://stackoverflow.com/questions/10603553/response-end-vs-httpcontext-current-applicationinstance-completerequest
                'response.end is considered harmful because it aborts a thread,  it cannot be error trapped
                '*** 2019-03-13 tested and works instead of Response.End()
                .Response.Flush()
                .Response.SuppressContent = True
                HttpContext.Current.ApplicationInstance.CompleteRequest()


            End With
        Catch ex As Exception

        End Try
    End Sub

    ''' <summary>
    ''' modifies and re-orders columns in a datatable. colNames is an array of existing names in desired order
    ''' Note: in NET3 declare the colNames() array before calling this routine, NET4 onward you can declare {} in the call itself
    ''' </summary>
    ''' <param name="dt">target datatable to have its columns reordered</param>
    ''' <param name="colNames">arrange of column names in desired order</param>
    ''' <param name="blDropRestOfCols">drop any column names not in colNames()</param>
    <Extension()>
    Sub setColumnOrder(ByRef dt As DataTable, ByVal colNames() As String, Optional ByVal blDropRestOfCols As Boolean = False)
        '*** modifies and re-orders columns in a datatable. colNames is an array of existing names in desired order
        '*** Note in net 3 you need to declare the colNames() array before you call this routine
        '*** dim a() as string={"what","the"}   dtcolumnOrder(dt,a)
        '*** whereas in net 4, you can do directly in the function call dtcolumnOrder(dt,{"what","the"})
        Try

            Dim i As Int16 = 0
            For Each cn In colNames
                If dt.Columns.Contains(cn) Then
                    dt.Columns(cn).SetOrdinal(i)
                    i += 1
                End If
            Next

            '*** now remove ones we don't need.  pain, easy to check if dt.contains, but not easy to check if colNames() contains because this is not a function of array
            'https://www.dreamincode.net/forums/topic/102273-how-to-use-arrayexist-method/
            'https://forums.asp.net/t/2085592.aspx?check+value+exist+in+an+array

            If blDropRestOfCols = False Then Exit Sub
            '*** need to enumerate backwards when removing
            For i = dt.Columns.Count - 1 To 0 Step -1
                If Not colNames.Contains(dt.Columns(i).ColumnName) Then
                    dt.Columns.RemoveAt(i)
                End If
            Next

        Catch ex As Exception
            dt = Nothing
        End Try

    End Sub


    ''' <summary>
    ''' serialises a datatable as base64 encoded string
    ''' </summary>
    ''' <param name="dt"></param>
    ''' <returns>base64 encoded string</returns>
    <Extension()>
    Function datatableToBase64(dt As DataTable) As String
        Dim ioStream As System.IO.MemoryStream = New System.IO.MemoryStream()
        Dim formatter As System.Runtime.Serialization.IFormatter = New System.Runtime.Serialization.Formatters.Binary.BinaryFormatter()
        formatter.Serialize(ioStream, dt)
        Dim b() As Byte = ioStream.GetBuffer()

        '*** URLtokenencode is apparently safer than TobBase64String
        '*** https://stackoverflow.com/questions/1228701/code-for-decoding-encoding-a-modified-base64-url-in-asp-net-framework
        Return HttpServerUtility.UrlTokenEncode(b)
        '        Return Convert.ToBase64String(b)
        ioStream.Dispose()
    End Function
    ''' <summary>
    ''' deserialises a base64 string to a datatable object
    ''' </summary>
    ''' <param name="sDatatable"></param>
    ''' <returns>datatable, or nothing if conversion fails</returns>
    <Extension()>
    Function datableFromBase64(sDatatable As String) As DataTable
        'recover the datatable from the base64 encoding.  return nothing if this fails, e.g. the encoding might be "no Data"
        'https://stackoverflow.com/questions/20512311/convert-datatable-to-byte-array
        '*** URLtokenencode is apparently safer than TobBase64String
        '*** https://stackoverflow.com/questions/1228701/code-for-decoding-encoding-a-modified-base64-url-in-asp-net-framework
        Try
            '*** URLtokendecode is apparently safer than FromBase64String
            ' Dim b() As Byte = System.Convert.FromBase64String(sTable)
            Dim b() As Byte = HttpServerUtility.UrlTokenDecode(sDatatable)
            Dim formatter As System.Runtime.Serialization.IFormatter = New System.Runtime.Serialization.Formatters.Binary.BinaryFormatter()
            Dim ioStream As System.IO.MemoryStream = New System.IO.MemoryStream(b)
            Return formatter.Deserialize(ioStream)
        Catch ex As Exception
            Return Nothing

        End Try

    End Function

    ''' <summary>
    ''' converts a datatable to a CSV string. Delimiter is comma and newline
    ''' </summary>
    ''' <param name="dt"></param>
    ''' <param name="blForExcel">handle leading zeros for XL compatability</param>
    ''' <returns>csv string</returns>
    <Extension()>
    Function DataTableToCSV(dt As DataTable, Optional blForExcel As Boolean = False) As String
        '*** 2022-04-22 works, but is not used
        Dim sb As New StringBuilder
        ''Write the headers.
        Dim iColCount As Integer = dt.Columns.Count
        For i = 0 To iColCount - 1
            sb.Append(dt.Columns(i).ColumnName)
            If (i < iColCount - 1) Then sb.Append(",")
        Next
        sb.Append(vbCrLf)

        '' Write rows.
        For Each dr As DataRow In dt.Rows
            For i = 0 To iColCount - 1
                'write non null values
                If Not Convert.IsDBNull(dr(i)) Then
                    'handle leading zeros for XL
                    If dr(i).ToString.StartsWith("0") And blForExcel Then
                        sb.Append("=""")
                        sb.Append(dr(i).ToString)
                        sb.Append("""")
                    Else
                        sb.Append(dr(i).ToString)
                    End If
                End If
                If (i < iColCount - 1) Then sb.Append(",")
            Next
            sb.Append(vbCrLf)
        Next
        Return sb.ToString
    End Function


#End Region

#Region "...CONTROLS AND BINDING..."
    <Extension()>
    Public Function sortACDC(ByVal dg As DataGrid, ByVal sSortExp As String)
        '*** modifies col header to include &uarr; or &darr; as well as toggling the
        '*** return state.  If ASC or DESC is provided in sSortExp this is the default starting dir
        Dim myC As DataGridColumn = Nothing
        Dim myC1 As DataGridColumn
        For Each myC1 In dg.Columns
            If myC1.SortExpression = sSortExp Then
                myC = myC1
            Else
                myC1.HeaderText = System.Text.RegularExpressions.Regex.Replace(myC1.HeaderText, "&uarr;|&darr;", "")
            End If
        Next

        If System.Text.RegularExpressions.Regex.IsMatch(sSortExp, ",") Then Return sSortExp '*** bail for complex sort expressions
        If myC Is Nothing Then Return sSortExp

        '*** If col has existing arrow, swap direction and toggle sort expression direction
        '*** Note sSortExp may NOT contain ASC or DESC so you cannot simply search for one of these
        '*** and replace it.  istead you have to append ASC or DESC
        If System.Text.RegularExpressions.Regex.IsMatch(myC.HeaderText, "&uarr;") Then
            myC.HeaderText = System.Text.RegularExpressions.Regex.Replace(myC.HeaderText, "&uarr;", "&darr;")
            sSortExp = System.Text.RegularExpressions.Regex.Replace(sSortExp, " ASC| DESC", "")
            sSortExp += " DESC"
        ElseIf System.Text.RegularExpressions.Regex.IsMatch(myC.HeaderText, "&darr;") Then
            myC.HeaderText = System.Text.RegularExpressions.Regex.Replace(myC.HeaderText, "&darr;", "&uarr;")
            sSortExp = System.Text.RegularExpressions.Regex.Replace(sSortExp, " ASC| DESC", "")
            sSortExp += " ASC"
            '*** if no arrows are present, means this is the first time we sort this col, so use its default
        ElseIf System.Text.RegularExpressions.Regex.IsMatch(sSortExp, "DESC") Then
            myC.HeaderText += "&nbsp;&darr;"
        Else '*** ASC, or no sort direction provided
            myC.HeaderText += "&nbsp;&uarr;"
        End If
        Return sSortExp
    End Function
    <Extension()>
    Public Function sortACDC(ByVal gv As GridView, ByVal sSortExp As String)
        '*** overload version. modifies col header to include &uarr; or &darr; as well as toggling the
        '*** return state.  If ASC or DESC is provided in sSortExp this is the default starting dir

        '*** IMPORTANT:  you need to set htmlEncode="false" on the column, else the gridview will escape the &uarr; and it will 
        '*** appear as &ampuarr; instead of the arrow character.  This will have a flow on impact for any characters displayed in the
        '*** column data fields also.
        '*** http://codeverge.com/asp.net.presentation-controls/gridview-and-special-characters/470523

        Dim myC As DataControlField = Nothing  'column in gridview
        Dim myC1 As DataControlField
        For Each myC1 In gv.Columns
            If myC1.SortExpression = sSortExp Then
                myC = myC1
            Else
                '*** for databound controls, this unfortunately displays as literal text, not as the arrow symbol
                myC1.HeaderText = System.Text.RegularExpressions.Regex.Replace(myC1.HeaderText, "&uarr;|&darr;", "")
            End If
        Next

        If System.Text.RegularExpressions.Regex.IsMatch(sSortExp, ",") Then Return sSortExp '*** bail for complex sort expressions
        If myC Is Nothing Then Return sSortExp

        '*** If col has existing arrow, swap direction and toggle sort expression direction
        '*** Note sSortExp may NOT contain ASC or DESC so you cannot simply search for one of these
        '*** and replace it.  istead you have to append ASC or DESC
        If System.Text.RegularExpressions.Regex.IsMatch(myC.HeaderText, "&uarr;") Then
            myC.HeaderText = System.Text.RegularExpressions.Regex.Replace(myC.HeaderText, "&uarr;", "&darr;")
            sSortExp = System.Text.RegularExpressions.Regex.Replace(sSortExp, " ASC| DESC", "")
            sSortExp += " DESC"
        ElseIf System.Text.RegularExpressions.Regex.IsMatch(myC.HeaderText, "&darr;") Then
            myC.HeaderText = System.Text.RegularExpressions.Regex.Replace(myC.HeaderText, "&darr;", "&uarr;")
            sSortExp = System.Text.RegularExpressions.Regex.Replace(sSortExp, " ASC| DESC", "")
            sSortExp += " ASC"
            '*** if no arrows are present, means this is the first time we sort this col, so use its default
        ElseIf System.Text.RegularExpressions.Regex.IsMatch(sSortExp, "DESC") Then
            myC.HeaderText += "&nbsp;&darr;"
        Else '*** ASC, or no sort direction provided
            myC.HeaderText += "&nbsp;&uarr;"
        End If
        Return sSortExp
    End Function
    <Extension()>
    Sub setColVis(ByVal g As DataGrid, ByVal c As String, ByVal v As Boolean)
        '*** 2015-05-04 overloaded version
        '*** show/hides the column with headerText=c
        Dim myC As DataGridColumn
        For Each myC In g.Columns
            If myC.HeaderText.ToUpper = c.ToUpper Then myC.Visible = v : Exit For
        Next

    End Sub
    <Extension()>
    Sub setColVis(ByVal g As GridView, ByVal c As String, ByVal v As Boolean)
        '*** 2015-05-04 overloaded version
        '*** show/hides the column with headerText=c
        Dim myC As DataControlField
        For Each myC In g.Columns
            If myC.HeaderText.ToUpper = c.ToUpper Then myC.Visible = v : Exit For
        Next
    End Sub
    <Extension()>
    Sub setDropDown(ByVal oDD As DropDownList, Optional ByVal oTable As DataTable = Nothing, Optional ByVal sVal As String = "")
        '*** 2014-11-17 modified to support optional 'bind' attribute on the DD, making it work same way as the doBindDataRow function
        '***  attribute bind usage; bind="text|value [nobind] [legacy] [blank]" where;
        '*** oldV attribute will hold existing value, oldT existing text.  these are bound on the aspx page, but sVal on the call will override
        '*** if no bind attribute is provided, oldT|oldV are used and a blank row is added

        If Not oTable Is Nothing Then
            oDD.DataSource = oTable
            oDD.DataBind()
        End If

        '*** backwards compatibility support
        If sVal = String.Empty Then
            If oDD.Attributes("oldV") & String.Empty <> String.Empty Then
                sVal = oDD.Attributes("oldV")
                If Not oDD.Items.FindByValue(sVal) Is Nothing Then oDD.Items.FindByValue(sVal).Selected = True 'backwards compatability support
            ElseIf oDD.Attributes("oldT") & String.Empty <> String.Empty Then
                sVal = oDD.Attributes("oldT") 'backwards compatability support
                If Not oDD.Items.FindByText(sVal) Is Nothing Then oDD.Items.FindByText(sVal).Selected = True
            End If
        End If

        '*** new code block, if bind attribute was provided, follow this
        If Not Regex.IsMatch(oDD.Attributes("bind") & String.Empty, "nobind", RegexOptions.IgnoreCase) Then
            Dim oItem As ListItem
            Dim blLegacy As Boolean = Regex.IsMatch(oDD.Attributes("bind") & String.Empty, "legacy", RegexOptions.IgnoreCase)
            Dim blBlank As Boolean = Regex.IsMatch(oDD.Attributes("bind") & String.Empty, "blank", RegexOptions.IgnoreCase)
            '*** 2009-12-14 some changes to the bind parameter and legacy parameter
            If Regex.IsMatch(oDD.Attributes("bind") & String.Empty, "value", RegexOptions.IgnoreCase) Then
                '*** find by value, but first check wether we are supporting legacy values (i.e. those not bound in the list)
                If oDD.Items.FindByValue(sVal) Is Nothing And blLegacy Then
                    oItem = New ListItem(sVal, sVal)
                    oDD.Items.Add(oItem) '*** add a legacy item
                    '*** now also add a blank if required (and hasn't just been added as a legacy item)
                Else
                    oItem = oDD.Items.FindByValue(sVal)
                End If
                oDD.SelectedIndex = oDD.Items.IndexOf(oItem)
            Else
                '*** default is to find by text
                If oDD.Items.FindByText(sVal) Is Nothing And blLegacy Then
                    oItem = New ListItem(sVal, sVal)
                    oDD.Items.Add(oItem)
                Else
                    oItem = oDD.Items.FindByText(sVal)
                End If
                oDD.SelectedIndex = oDD.Items.IndexOf(oItem)
            End If  '*** value test

            '*** now add a blank if required, and select it if required
            If blBlank Then
                '*** add a blank if one does not already exist
                If CBool(oDD.Items.FindByValue(String.Empty) Is Nothing) Then oDD.Items.Add(New ListItem(String.Empty, String.Empty))
                '*** If we do not have a valid oItem from before, then select this blank value
                If oItem Is Nothing Then
                    oItem = oDD.Items.FindByValue(String.Empty)
                    oDD.SelectedIndex = oDD.Items.IndexOf(oItem)
                End If
            End If '*** blank 
        End If
    End Sub
    ''' <summary>
    ''' In the gridview headerrow, define some filter controls such as dropdowns, textboxes and checkboxes. Their ID must start with flt_something
    ''' this class will populate those dropdowns based on the table data. It will persist them and their states through page serves via the _cloneControl array list
    ''' Note: create an overload for your showData() routine used to populate the gridView as a generic handler to call a rebind of the gridView
    ''' i.e. showData(sender As Object, e As EventArgs) which itself calls showData() when a change occurs on a flt_control
    ''' </summary>
    Class headFilter
        '*** user class that handles flt_controls in the headerrow 
        '*** Note: the flt_controls in the header need to call back to a genericFilterEvent(sender As Object, e As EventArgs) which will call the showGrid() routine
        '*** Additionally, you can set the grid.visible=false elsewhere to signal to th showGrid() routine to rebind the dropdowns.
        '*** see use examples - it is necessary to populate the filter dropdowns when the grid is first populated, and to pull the filer
        '*** values back into a parameter query


        'has a reference to the headerrow.  can ask it for the current value of a given control therein
        'https://stackoverflow.com/questions/5299435/how-to-create-control-arrays-in-vb-net
        'https://stackoverflow.com/questions/5555674/create-a-copy-of-an-asp-net-control-object
        'we need to make a COPY of the controls in the headerrow

        '*** not likely this class is serializable because it contains arraylists of non serializeable web controls
        '*** that's not a problem because we don't need to store it in the viewstate

        Dim _controlClone As New ArrayList 'will be adding controlClones
        Dim _gv As GridView 'pointer to the datagrid
        ''' <summary>
        ''' Instantiate a new headFilter class
        ''' </summary>
        ''' <param name="gv">optional reference to the gridview containing the head filter</param>
        Public Sub New(Optional gv As GridView = Nothing)
            _gv = gv
        End Sub
        ''' <summary>
        ''' Captures all the filter controls in the gridview headerrow 
        ''' and clones the filter objects therein, thus snapshotting them
        ''' </summary>
        ''' <param name="gv">gridview reference, optional if was set in New()</param>
        ''' <param name="disableSQLsafe">optionally disable SQL safing of inputs</param>
        Sub setHR(Optional gv As GridView = Nothing, Optional disableSQLsafe As Boolean = False)
            If gv Is Nothing Then gv = _gv

            Dim temp As New ArrayList 'holds references to existing headerrow objects
            For Each fhc As DataControlFieldHeaderCell In gv.HeaderRow.Controls
                For Each crl As Control In fhc.Controls
                    If TypeOf (crl) Is DropDownList Then
                        temp.Add((DirectCast(crl, DropDownList)))
                    ElseIf TypeOf (crl) Is TextBox Then
                        Dim tb As TextBox = TryCast(crl, TextBox)
                        If Not disableSQLsafe Then tb.Text = tb.Text.sqlSafe.Trim
                        temp.Add((DirectCast(crl, TextBox)))
                    ElseIf TypeOf (crl) Is CheckBox Then
                        temp.Add((DirectCast(crl, CheckBox)))
                    End If
                Next
            Next
            'clone the headerrow objects
            _controlClone = temp.Clone

        End Sub
        'not in use
        Function cloneMe(o As Object) As Object
            ' https://stackoverflow.com/questions/78536/deep-cloning-objects
            Dim t As Type = o.GetType
            If t.IsSerializable = False Then Throw New ArgumentException("The type must be serializable.", NameOf(o))
            'If (ReferenceEquals(o, Nothing)) Then Return Nothing

            Dim stream As New MemoryStream()
            Dim formatter As IFormatter = New BinaryFormatter()
            formatter.Serialize(stream, o)
            stream.Seek(0, SeekOrigin.Begin)
            'Return TryCast(formatter.Deserialize(stream), t)
            Return formatter.Deserialize(stream)

        End Function


        ''' <summary>
        ''' restores the cloned filter controls with their values and selections to the header row
        ''' use this after you have databound the gridview
        ''' </summary>
        ''' <param name="gv">gridview ref, optional if it was set in New()</param>
        Sub restoreHR(Optional gv As GridView = Nothing)
            If gv Is Nothing Then gv = _gv
            For Each ctrlToRestore As Control In _controlClone
                Dim ctrlTemp As Control = gv.HeaderRow.FindControl(ctrlToRestore.ID)
                If ctrlTemp IsNot Nothing Then
                    '*** you cannot assign, instead you must copy contents of cloned control back

                    If TypeOf (ctrlTemp) Is DropDownList Then
                        TryCast(ctrlTemp, DropDownList).Items.Clear()
                        For Each li As ListItem In TryCast(ctrlToRestore, DropDownList).Items
                            TryCast(ctrlTemp, DropDownList).Items.Add(li)
                        Next
                    ElseIf TypeOf (ctrlTemp) Is TextBox Then
                        TryCast(ctrlTemp, TextBox).Text = TryCast(ctrlToRestore, TextBox).Text
                    ElseIf TypeOf (ctrlTemp) Is CheckBox Then
                        TryCast(ctrlTemp, CheckBox).Checked = TryCast(ctrlToRestore, CheckBox).Checked
                    End If

                End If
            Next

        End Sub
        ''' <summary>
        ''' returns an arraylist of cloned controls, exposing the internal variable
        ''' </summary>
        ''' <returns></returns>
        Function getClones() As ArrayList
            Return _controlClone
        End Function
        ''' <summary>
        ''' return specific control clone based on its id
        ''' </summary>
        ''' <param name="id">ID of the filter control</param>
        ''' <returns>the control</returns>
        Function getControlClone(id As String) As Control
            For Each c As Control In _controlClone
                If c.ID.ToUpper = id.ToUpper Then Return c
            Next
            Return Nothing
        End Function
        ''' <summary>
        ''' returns a filter string based on the control values/ pairs. Needs a reference to the gv as it iterates the pairs.
        ''' </summary>
        ''' <param name="gv">gridview</param>
        ''' <param name="id">ID of the filter control</param>
        ''' <returns>a string value to use as an SQL parameter value in a LIKE clause</returns>
        Public Function getFilter(gv As GridView, id As String) As String
            '*** returns a filter string based on the control values/ pairs, which is why it needs a headerrow ref to 
            '*** discover the pairs
            '*** ignores ck setting.

            Dim myTB As TextBox = TryCast(getControlClone(id), TextBox)
            If myTB IsNot Nothing Then myTB.Text = myTB.Text.sqlSafe.Trim
            Dim myDD As DropDownList = TryCast(getControlClone(id), DropDownList)
            Dim myCB As CheckBox = TryCast(getControlClone(id), CheckBox)

            '*** test for all three as Nothing, throw an error
            If myTB Is Nothing And myDD Is Nothing And myCB Is Nothing Then Throw New ArgumentException("No control found for " & id)

            'else we need to find the other part of the TB-DD pair, if there is one. these would be in the fieldheadercell

            If myCB IsNot Nothing Then
                Return myCB.Checked.ToString
            End If

            If myTB Is Nothing Then
                '*** look for the tb
                For Each o As Control In gv.HeaderRow.FindControl(id).Parent.Controls
                    If TypeOf (o) Is TextBox Then myTB = o
                Next
            End If

            If myDD Is Nothing Then
                '*** look for the dd
                For Each o As Control In gv.HeaderRow.FindControl(id).Parent.Controls
                    If TypeOf (o) Is DropDownList Then myDD = o
                Next
            End If


            '*** Is this just a dropdown
            If myTB Is Nothing Then
                Select Case myDD.SelectedValue.ToUpper
                    Case "ALL"
                        Return "%"
                    Case Else
                        Return myDD.SelectedValue
                End Select
            End If

            '*** is this just a textbox
            If myDD Is Nothing Then
                If myTB.Text.Length = 0 Then Return "%"
                Return myTB.Text 'exact match required
            End If

            '*** have a tb-dd pair
            Select Case myDD.SelectedValue.ToUpper
                Case "ALL"
                    Return "%"
                Case "CONTAINS"
                    Return "%" & myTB.Text.sqlSafe & "%"
                Case "BEGINS WITH"
                    Return myTB.Text.sqlSafe & "%"
                Case "ENDS WITH"
                    Return "%" & myTB.Text.sqlSafe
                Case Else
                    Return myDD.SelectedValue
            End Select



        End Function

        ''' <summary>
        ''' binds to a dropdown CLONES, on expectation that column in the datatable=datavaluefield of a dropdown.  
        ''' add a custom attribute of ACBE=true to add All/contains/begins/ends to the dropdown
        ''' </summary>
        ''' <param name="id">id of filter control</param>
        ''' <param name="dt">datatable used to bind gridview</param>
        ''' <param name="blACBE">add All/contains/begins/ends</param>
        Sub bindDropddown(id As String, dt As DataTable, Optional blACBE As Boolean = False)
            Dim myDD As DropDownList = TryCast(getControlClone(id), DropDownList)
            If myDD Is Nothing Then Exit Sub

            myDD.Items.Clear()
            '*** assume list is distinct, clear it so that it does not already contain these items
            '*** need to sort the list

            Dim myview = dt.DefaultView
            myview.Sort = dt.Columns(0).ColumnName

            For Each myR As DataRowView In myview
                myDD.Items.Add(New ListItem(myR(0).ToString, myR(0).ToString))
            Next



            '*** default selection is all
            myDD.Items.Insert(0, New ListItem("All", "All") With {.Selected = True})
            '*** optionally add
            If Not blACBE Then Exit Sub
            myDD.Items.Insert(1, New ListItem("Ends with", "Ends with"))
            myDD.Items.Insert(1, New ListItem("Begins with", "Begins with"))
            myDD.Items.Insert(1, New ListItem("Contains", "Contains"))

        End Sub
        ''' <summary>
        ''' Encapsulation method. Databinds all the filter dropdowns in the header row using distinct values in dt
        ''' Add ACBE='true' to the dropdown if you wish to add ALL,CONTAINS,BEFORE,ENDS to the options
        ''' </summary>
        ''' <param name="dt">datatable used as the gridview datasource. Optional if you called New() with a ref to the gridview AND subsequently bound a table to it</param>
        Sub bindAllDropdowns(Optional dt As DataTable = Nothing)
            If dt Is Nothing Then dt = _gv.DataSource
            For Each c As Control In _controlClone
                If TypeOf (c) Is DropDownList Then
                    Dim dd As DropDownList = DirectCast(c, DropDownList)
                    Dim ACBE As String = dd.Attributes("ACBE")
                    Me.bindDropddown(dd.ID, dt.DefaultView.ToTable(True, dd.DataValueField), CBool(ACBE = "true"))
                    dd = Nothing
                End If
            Next
        End Sub

        ''' <summary>
        ''' Encapsulation method. Call with sSQL holding the SELECT clause. Sub will append a WHERE statement to this with params and also prepare the param collection
        ''' leaving the OleDbDataAdapter ready to execute
        ''' </summary>
        ''' <param name="oDA">OleDbDataAdapter containing base SQL SELECT statement</param>
        ''' <param name="sFieldNames">array of field names</param>
        ''' <param name="sControlIDs">array of corresponding control IDs in the gv headerrow</param>
        ''' <param name="gv">gridview optional if it was set in New()</param>

        Public Sub getSQLwithParams(ByRef oDA As OleDbDataAdapter, sFieldNames() As String, sControlIDs() As String, Optional gv As GridView = Nothing)
            If gv Is Nothing Then gv = _gv
            Dim sb As New StringBuilder
            sb.Append(oDA.SelectCommand.CommandText)
            sb.Append(" WHERE ")
            For i As Integer = 0 To sControlIDs.Count - 1
                sb.Append(sFieldNames(i))
                sb.Append(" LIKE @p")
                sb.Append(i.ToString)
                sb.Append(" AND ")
                Dim newP As New OleDbParameter With {.DbType = DbType.String, .Size = 255, .ParameterName = "@p" & i.ToString}
                newP.Value = Me.getFilter(gv, sControlIDs(i))
                oDA.SelectCommand.Parameters.Add(newP)
            Next

            '*** remove trailling AND
            sb.Remove(sb.Length - 5, 5)
            oDA.SelectCommand.CommandText = sb.ToString

        End Sub



    End Class

#End Region


#Region "...HELPER FUNCTIONS..."

    Function fnSpaceToNull(ByVal sText As String) As Object
        If sText = String.Empty Then Return DBNull.Value
        Return sText
    End Function
    Function fnWkgDays(ByVal d1 As Date, ByVal d2 As Date) As Long
        Dim n As Long
        Dim res As Long = 0
        For n = 1 To DateDiff("d", d1, d2)
            If Weekday(DateAdd("d", n, d1)) > 1 And Weekday(DateAdd("d", n, d1)) < 7 Then res += 1
        Next
        Return res
    End Function
    ''' <summary>
    ''' if x is a date, subtracts timeOffset to adjust the timezone
    ''' </summary>
    ''' <param name="x">a date</param>
    ''' <param name="timeOffset">hours</param>
    ''' <returns>date</returns>
    Function adjTZO(ByVal x As Object, ByVal timeOffset As String) As Object
        '*** adjusts for timezone
        Try
            If IsDate(x) Then
                x = CDate(x).AddHours(-1 * timeOffset)
            End If
        Catch
        End Try
        Return x
    End Function
    ''' <summary>
    ''' strips unsafe chars from user input
    ''' </summary>
    ''' <param name="s">input string</param>
    ''' <param name="blAllowSpecial">allow ',." all quotes are escaped</param>
    ''' <returns>safe string</returns>
    <Extension()>
    Function sqlSafe(ByVal s As String, Optional blAllowSpecial As Boolean = False) As String
        '*** 2021-07-13 tighen this up to strip any chars which are not pure alpha or numeric, optionally allow apostrophies, dot and hypen
        '**** \x27 is apost \x22 is quote  \x2E is dot \x2C is comma \x2B is neg symbol
        Try
            If blAllowSpecial Then
                'escape apostrophy and quote, then allow these
                s = s.Replace("'", "''")
                s = s.Replace("""", """""")
                '*** strip all non safe characters 
                'Return Regex.Replace(s, "[^\w \x22\x27\x2E\x2C]+", String.Empty)
                Return Regex.Replace(s, "[^a-zA-Z0-9_\-]+", String.Empty)
            Else
                '*** strip all but alpha
                Return Regex.Replace(s, "[^\w ]+", String.Empty)
            End If

        Catch
            Return String.Empty
        End Try

    End Function
    ''' <summary>
    ''' retains only the part of the user input which matches the regex pattern. case insensitive
    ''' </summary>
    ''' <param name="s">input string</param>
    ''' <param name="sRegex">regex pattern, do not use groups</param>
    ''' <returns>first exactly matched pattern</returns>
    <Extension()>
    Function sqlSafe(ByVal s As String, sRegex As String) As String
        '*** 2021-07-13 overload. only return the part of the string that exactly matches sRegex.  Case insensitive.
        '*** e.g. if you expect a date param as "yyyy-MM" then call with sRegex:= \d{4}-\d{2}
        Try
            Dim m As Match = Regex.Match(s, "(" & sRegex & ")", RegexOptions.IgnoreCase)
            If m.Success Then Return m.Value
            Return String.Empty
        Catch
            Return String.Empty
        End Try

    End Function

    <Extension()>
    Function escapeSafe(ByVal s As String) As String
        Dim sb As New StringBuilder(s.Length)
        Dim i As Integer
        '*** mid is 1 based
        For i = 1 To s.Length
            Select Case Mid(s, i, 1)
                Case "[", "]", "%", "*"
                    sb.Append("[")
                    sb.Append(Mid(s, i, 1))
                    sb.Append("]")

                Case "'"
                    sb.Append("''")
                Case Else
                    sb.Append(Mid(s, i, 1))
            End Select

        Next

        Return sb.ToString

    End Function

    <Extension()>
    Sub StreamFile(ByVal pg As Page, ByVal sFullPath As String)
        '*** will stream the target file to the client browser.  This has the advantage that .xlsx files will work properly over https://
        '*** the problem we had with hyperlinks was that the .xlsx file got corrupted over https and we had to server over http instead

        '*** 2014-10-31 fix for Firefox
        '*** http://techblog.procurios.nl/k/news/view/15872/14863/mimetype-corruption-in-firefox.html
        '*** the fix is below.  THIS WORKS on IE, FF and Chrome

        '*** 2019-01-23 made an extension to page object, and ThreadAbortException is now properly handled

        Dim tgByte() As Byte = Nothing
        With pg.Response
            Try
                Dim tgFStream As New IO.FileStream(sFullPath, IO.FileMode.Open, IO.FileAccess.Read)
                Dim tgBinaryReader As New IO.BinaryReader(tgFStream)
                tgByte = tgBinaryReader.ReadBytes(Convert.ToInt32(tgFStream.Length))
                '*** write the response
                .Clear()
                .OutputStream.Write(tgByte, 0, tgByte.Length)

                '*** strange bug with Firefox downloads.  If the filename contains spaces, FF will break the filename at the first space, lose the file suffix
                '*** and won't know how to open the file.  If we server.URLencode it, the spaces come across as + symbols, the file is correctly recognised but
                '*** we obviously have + now instead of space.
                '*** http://stackoverflow.com/questions/93551/how-to-encode-the-filename-parameter-of-content-disposition-header-in-http
                '*** The theoretically correct syntax for use of UTF-8 in Content-Disposition is just crazy: filename*=UTF-8''foo%c3%a4 (yes, that's an asterisk, and no quotes except an empty single quote in the middle)
                '*** YES, this does work with FireFox but we also need to use Uri.EscapeDataString to encode spaces as %20 rather than + (which is what Server.EncodeURL does).
                .AddHeader("Content-Disposition", "attachment; filename*=UTF-8''" & Uri.EscapeDataString(System.IO.Path.GetFileName(tgFStream.Name)))
                .AddHeader("Content-Length", tgByte.Length.ToString())
                .ContentType = "application/octet-stream"

                '*** instead of response.end() use Flush(), SupressContent and CompleteRequest()
                '*** https://stackoverflow.com/questions/1087777/is-response-end-considered-harmful
                '*** https://weblog.west-wind.com/posts/2008/May/26/Ending-a-Response-without-ResponseEnd-Exceptions
                '*** http://web.archive.org/web/20101224113858/http://www.c6software.com/codesolutions/dotnet/threadabortexception.aspx

                tgBinaryReader.Close()
                '*** 2020-04-16 SCA: tgFstream can be disposed of more than once.  PENDING FIX.
                tgFStream.Close()

                '*** 2019-03-13 this should work Response.End()
                .Flush()
                .SuppressContent = True
                HttpContext.Current.ApplicationInstance.CompleteRequest()

            Catch ex1 As System.Threading.ThreadAbortException
                '*** handle this abort cleanly so we don't write an error message to file
                '*** response.end triggers the thread about and we need this to stop the entire page HTML streaming as well as the desired file
                'System.Threading.Thread.ResetAbort()
                '*** .ResetAbort will get past the error and cause the page HTML to stream, which we don't want
            Catch ex As Exception
                '*** all other error types we wish to capture and report to user
                writeAudit(ex.ToString, "streamfile")
                .Write("Sorry an error occured retreiving the file " & ex.ToString)
            Finally

            End Try
        End With
    End Sub

    ''' <summary>
    ''' set the active multiview from a text value, matching it to the view ID
    ''' </summary>
    ''' <param name="mv">Multiview object</param>
    ''' <param name="sID">string representing the ID of the target view</param>
    ''' <returns>returns true if successful, false if sID cannot be matched</returns>
    <Extension>
    Function setActiveViewByIDText(mv As MultiView, sID As String) As Boolean
        '*** given the ID of view, will set this view to be the active view.  saves you needing to know the ordinal index. returns false if not found
        For Each v As View In mv.Views
            If v.ID.ToUpper = sID.ToUpper Then
                mv.SetActiveView(v)
                Return True
            End If

        Next
        Return False
    End Function
    ''' <summary>
    ''' set the active menu item matching its value to a given text string
    ''' </summary>
    ''' <param name="m">Menu object</param>
    ''' <param name="v">target menu item.value case insensitive</param>
    ''' <returns>true if successful</returns>
    <Extension>
    Function setActivewMenuItemByValue(m As Menu, v As String) As Boolean
        For Each mi As MenuItem In m.Items
            If String.Compare(mi.Value, v, True) = 0 Then
                mi.Selected = True
                Return True
            End If

        Next


        Return False
    End Function




    ''' <summary>
    ''' convert a date to an ISO string
    ''' </summary>
    ''' <param name="dt">input date</param>
    ''' <param name="nChars">left most part of ISO string to return</param>
    ''' <returns>yyyy-MM-dd or part thereof</returns>
    <Extension> Function ToISOdateString(dt As Date, Optional nChars As Integer = 0) As String
        Try
            If nChars = 0 Then Return Format(dt, "yyyy-MM-dd")
            Return Left(Format(dt, "yyyy-MM-dd"), nChars)
        Catch ex As Exception
            Return String.Empty
        End Try

    End Function

#End Region


#Region "...EMAIL..."
    Function sendMail(ByVal sTo As String, ByVal sCC As String, ByVal sFrom As String, ByVal sSubject As String, ByVal sBody As String) As Boolean
        '*** 2014-05-28 re-written for net 2.  Need to build an overload version to handle attachments
        '*** 2014-06-27 the mail server host name is only accessible through the client object, so the TEST routine has been moved lower down

        Using myMail As New System.Net.Mail.MailMessage
            Try
                If sFrom.Trim = String.Empty Then
                    myMail.From = New System.Net.Mail.MailAddress("noReplies@au.verizon.com", "PCM server no replies")
                Else
                    myMail.From = New System.Net.Mail.MailAddress(sFrom)
                End If

                '*** 2014-06-27 sTo and sCC might be ; separated strings.  We have to process each member and add separately to the mail object
                For Each s As String In Split(sTo, ";")
                    If s.Trim <> String.Empty Then myMail.To.Add(New System.Net.Mail.MailAddress(s))
                Next

                For Each s As String In Split(sCC, ";")
                    If s.Trim <> String.Empty Then myMail.CC.Add(New System.Net.Mail.MailAddress(s))
                Next

                myMail.Subject = sSubject
                myMail.Body = sBody
                myMail.BodyEncoding = System.Text.Encoding.ASCII
                ' MyMail.BodyFormat = System.Web.Mail.MailFormat.Text
                myMail.Priority = System.Net.Mail.MailPriority.High
                Dim myClient As New System.Net.Mail.SmtpClient
                '*** the client will pick up the smtp server address from the web.config file
                If myClient.Host = "TEST" Then
                    writeAudit(String.Concat("to:", sTo, vbCrLf, "cc:", sCC, vbCrLf, "From:", sFrom, vbCrLf, "subject:", sSubject, vbCrLf, "body:", sBody), "TEST_email")
                    Return True
                Else
                    myClient.Send(myMail)
                    Return True
                End If


            Catch ex As Exception
                writeAudit(ex.ToString, "sendmail")
                writeAudit(String.Concat("to:", sTo, vbCrLf, "cc:", sCC, vbCrLf, "From:", sFrom, vbCrLf, "subject:", sSubject, vbCrLf, "body:", sBody), "email_debug")
                Return False
            Finally
            End Try
        End Using
    End Function
    Function sendMail(ByVal sTo As String, ByVal sCC As String, ByVal sFrom As String, ByVal sSubject As String, ByVal sBody As String, ByVal sAttachmentPaths As String) As Boolean
        '*** overload version of sendMail to handle attachments.  These must be full paths separated by a comma.
        '*** 2014-06-27 the mail server host name is only accessible through the client object, so the TEST routine has been moved lower down
        Using myMail As New System.Net.Mail.MailMessage
            Try
                If sFrom.Trim = String.Empty Then
                    myMail.From = New System.Net.Mail.MailAddress("noReplies@au.verizon.com", "PCM server no replies")
                Else
                    myMail.From = New System.Net.Mail.MailAddress(sFrom)
                End If

                '*** 2014-06-27 sTo and sCC might be ; separated strings.  We have to process each member and add separately to the mail object
                For Each s As String In Split(sTo, ";")
                    If s.Trim <> String.Empty Then myMail.To.Add(New System.Net.Mail.MailAddress(s))
                Next

                For Each s As String In Split(sCC, ";")
                    If s.Trim <> String.Empty Then myMail.CC.Add(New System.Net.Mail.MailAddress(s))
                Next

                myMail.Subject = sSubject
                myMail.Body = sBody
                myMail.BodyEncoding = System.Text.Encoding.ASCII
                ' MyMail.BodyFormat = System.Web.Mail.MailFormat.Text
                myMail.Priority = System.Net.Mail.MailPriority.High

                For Each sPath As String In sAttachmentPaths.Split(",")
                    myMail.Attachments.Add(New System.Net.Mail.Attachment(sPath))
                Next

                Dim myClient As New System.Net.Mail.SmtpClient
                '*** the client will pick up the smtp server address from the web.config file
                If myClient.Host = "TEST" Then
                    writeAudit(String.Concat("to:", sTo, vbCrLf, "cc:", sCC, vbCrLf, "From:", sFrom, vbCrLf, "subject:", sSubject, vbCrLf, "body:", sBody), "TEST_email")
                    Return True
                Else
                    myClient.Send(myMail)
                    Return True
                End If

            Catch ex As Exception
                writeAudit(ex.ToString, "sendMailWithAttachment")
                writeAudit(String.Concat("to:", sTo, vbCrLf, "cc:", sCC, vbCrLf, "From:", sFrom, vbCrLf, "subject:", sSubject, vbCrLf, "body:", sBody, vbCrLf, "sAttachmentPaths:", sAttachmentPaths), "email_debug")
                writeAudit(myMail.To.ToString, "myMail.To.ToString")
                writeAudit(myMail.From.ToString, "myMail.From.ToString")
                writeAudit(myMail.CC.ToString, "myMail.cc.ToString")
                Return False
            Finally
            End Try
        End Using
    End Function
#End Region
    Function isLocalURL(a As String, b As String) As Boolean
        '*** returns true if the origin and requested destination are the same
        'can we feed with request and pathinfo?

        'in the headers
        'Referer http: //localhost:61603/PCManalytics_Customer.aspx
        'Origin  http: //localhost:61603

        'Sec-Fetch-Site	same-origin    this is not avail in FF  https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Fetch-Site

        'actually i don't think there is a risk.  we strip the pathinfo and then use the http referrer to redirect back to the site, and since the referrer is our site,
        'we are always going to point to ourseves.  if bogus site is put in path info, it gets pulled into pathinfo variable but it is not directed to.


        Return False
    End Function

#Region "...LDAP..."
    '*** requires a reference to System.DirectoryServices and System.DirectoryServices.AccountManagement
    '*** LDAP allows us to pull the email and name/surname plus manager ID of a given user.  Its possible to crawl up the directory, but you do need to know the domain
    '*** and this is not captured for users who report to the US.  However, we can try/guess using the USWIN domain and this will work, noting that the USWIN domain will
    '*** return fewer attributes than the EMEA-DSMAIN domain.

    '*** using LDAP, there is no need for users to provide their email or manager's email when registering and there's no need to validate their email address.

    'returns a LDAP details for the user in a datatable. if no results, table has zero rows
    Function getLDAP(sLogonUser As String) As DataTable
        Dim dtResult As New DataTable("LDAP")
        dtResult.Columns.Add(New DataColumn("givenname", GetType(String)) With {.MaxLength = 50})
        dtResult.Columns.Add(New DataColumn("sn", GetType(String)) With {.MaxLength = 50})
        dtResult.Columns.Add(New DataColumn("mail", GetType(String)) With {.MaxLength = 255})
        dtResult.Columns.Add(New DataColumn("vzmanager", GetType(String)) With {.MaxLength = 30, .DefaultValue = ""})
        dtResult.Columns.Add(New DataColumn("c", GetType(String)) With {.MaxLength = 50})


        Dim domains() As String = {"EMEA-DSMAIN", "USWIN"}

        Try
            For Each domain As String In domains
                'userprincipalname santokh.sanghera@EMEA.dsmain.com
                'userprincipalname v817353@EMEA.dsmain.com
                'samaccountname santokh.sanghera  and we can guess at EMEA-DSMAIN

                Dim searcher = New DirectorySearcher(String.Concat("LDAP://", domain))

                searcher.Filter = String.Concat("(&(ObjectClass=person)(sAMAccountName=", sLogonUser.Split("\\").Last(), "))")
                Dim result As SearchResult = searcher.FindOne()
                If IsNothing(result) Then Continue For

                Dim myR As DataRow = dtResult.NewRow()
                '*** pull fields
                For Each o As System.Collections.DictionaryEntry In result.Properties
                    If dtResult.Columns.Contains(o.Key.ToString) Then
                        myR.Item(o.Key.ToString) = o.Value(0).ToString
                    End If
                Next

                dtResult.Rows.Add(myR)
                Return dtResult
            Next

            '*** failed to find any diretory entries on any domains, return an empty table
            Return dtResult

        Catch ex As Exception
            writeAudit("getLDAP " & ex.ToString, "system")
            Return dtResult
        End Try

    End Function
    Function getLDAP(lEmployeeNumber As Long) As DataTable
        Dim dtResult As New DataTable("LDAP")
        dtResult.Columns.Add(New DataColumn("givenname", GetType(String)) With {.MaxLength = 50})
        dtResult.Columns.Add(New DataColumn("sn", GetType(String)) With {.MaxLength = 50})
        dtResult.Columns.Add(New DataColumn("mail", GetType(String)) With {.MaxLength = 255})
        dtResult.Columns.Add(New DataColumn("vzmanager", GetType(String)) With {.MaxLength = 30, .DefaultValue = ""})
        dtResult.Columns.Add(New DataColumn("c", GetType(String)) With {.MaxLength = 50})


        Dim domains() As String = {"EMEA-DSMAIN", "USWIN"}

        Try
            For Each domain As String In domains
                'userprincipalname santokh.sanghera@EMEA.dsmain.com
                'userprincipalname v817353@EMEA.dsmain.com
                'samaccountname santokh.sanghera  and we can guess at EMEA-DSMAIN

                Dim searcher = New DirectorySearcher(String.Concat("LDAP://", domain))

                searcher.Filter = String.Concat("(&(ObjectClass=person)(employeenumber=", lEmployeeNumber.ToString, "))")
                Dim result As SearchResult = searcher.FindOne()
                If IsNothing(result) Then Continue For

                Dim myR As DataRow = dtResult.NewRow()

                '*** pull fields
                For Each o As System.Collections.DictionaryEntry In result.Properties
                    If dtResult.Columns.Contains(o.Key.ToString) Then
                        myR.Item(o.Key.ToString) = o.Value(0).ToString
                    End If
                Next

                dtResult.Rows.Add(myR)
                Return dtResult
            Next

            '*** failed to find any diretory entries on any domains, return an empty table
            Return dtResult

        Catch ex As Exception
            writeAudit("getLDAP " & ex.ToString, "system")
            Return dtResult
        End Try

    End Function



#End Region



End Module