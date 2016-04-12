unit WebUtils;

{$mode objfpc}{$H+}

interface
	uses
		base64, httpdefs, AccountController, Utils, DashboardContainer;

	procedure SetAuthCookie(AResponse: TResponse; const userid: int64);
	procedure ClearAuthCookie(AResponse: TResponse);
	procedure GetUsernameAndPassword(ARequest: TRequest; var username, password: string);
	procedure AddPermission(ARequest: TRequest; AResponse: TResponse; dashboardid: TDashboardId);

	function IsAuthorized(ARequest: TRequest): string;
	function GetAuthCookie(ARequest: TRequest): string;
	function GetQueryUserId(ARequest: TRequest): TUserId;
	function GetQueryDashboardId(ARequest: TRequest): TUserId;
	function GetCurrentUserId(ARequest: TRequest): TUserId;
	function HavePermission(ARequest: TRequest; dashboard: TDashboardId): string;
	function GetPermittedDashboards(ARequest: TRequest): TDashboardIds;

implementation

	const
		AuthCookieName = 'auth';

	procedure SetAuthCookie(AResponse: TResponse; const value: string);
	var
		cookie: TCookie;
	begin
		cookie := AResponse.Cookies.Add;
		cookie.Name := AuthCookieName;
		cookie.Value := EncodeStringBase64(value);
		cookie.HttpOnly := True;
		cookie.Path := '/';
	end;

	procedure SetAuthCookie(AResponse: TResponse; const userid: int64);
	begin
		SetAuthCookie(AResponse, AccountManager.GetAuthToken(userid));
	end;

	procedure ClearAuthCookie(AResponse: TResponse);
	begin
		SetAuthCookie(AResponse, '');
	end;

	procedure GetUsernameAndPassword(ARequest: TRequest; var username, password: string);
	begin
		username := ARequest.ContentFields.Values['username'];
		password := ARequest.ContentFields.Values['password'];
	end;

	function IsAuthorized(ARequest: TRequest): string;
	var
		token: string;
	begin
		token := GetAuthCookie(ARequest);
		if token = '' then
			exit('can''t found cookie');
		result := AccountManager.IsAuthorized(token);
	end;

	function GetAuthCookie(ARequest: TRequest): string;
	var
		cookie: string;
	begin
		cookie := ARequest.CookieFields.Values[AuthCookieName];
		if cookie = '' then
			exit('');
		result := DecodeStringBase64(cookie);
	end;

	function GetQueryUserId(ARequest: TRequest): TUserId;
	begin
		result := StrToQWord(ARequest.QueryFields.Values['userid']);
	end;

	function GetQueryDashboardId(ARequest: TRequest): TUserId;
	begin
		result := StrToQWord(ARequest.QueryFields.Values['dashboardid']);
	end;

	function GetCurrentUserId(ARequest: TRequest): TUserId;
	var
		token: string;
	begin
		token := GetAuthCookie(ARequest);
		if token = '' then
			exit(0);
		result := AccountManager.GetCurrentUserId(token);
	end;

	function HavePermission(ARequest: TRequest; dashboard: TDashboardId): string;
	var
		token: string;
	begin
		token := GetAuthCookie(ARequest);
		if token = '' then
			exit('Unauthorized');
		result := AccountManager.HavePermission(token, dashboard);
	end;

	procedure AddPermission(ARequest: TRequest; AResponse: TResponse; dashboardid: TDashboardId);
	var
		token: string;
	begin
		token := GetAuthCookie(ARequest);
		token := AccountManager.AddPermission(token, dashboardid);
		SetAuthCookie(AResponse, token);
	end;

	function GetPermittedDashboards(ARequest: TRequest): TDashboardIds;
	var
		token: string;
	begin
		token := GetAuthCookie(ARequest);
		if token = '' then
			exit(nil);
		result := AccountManager.GetPermittedDashboards(token);
	end;
end.
