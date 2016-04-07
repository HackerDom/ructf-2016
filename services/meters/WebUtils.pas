unit WebUtils;

{$mode objfpc}{$H+}

interface
	uses
		httpdefs, AccountController, SysUtils;

	procedure SetAuthCookie(AResponse: TResponse; const userid: int64);
	procedure ClearAuthCookie(AResponse: TResponse);
	procedure GetUsernameAndPassword(ARequest: TRequest; var username, password: string);
	procedure SendUnauthorized(AResponse: TResponse);

	function IsAuthorized(ARequest: TRequest): boolean;
	function GetAuthCookie(ARequest: TRequest): string;
	function GetQueryUserId(ARequest: TRequest): TUserId;

	function GetTemplate(const path: string): string;

implementation
	const
		AuthCookieName = 'auth';

	function StrToQWord(const s: string): QWord;
	var
		i: longint;
	begin
		result := 0;
		for i := 1 to length(s) do
		begin
			if (s[i] < '0') or ('9' < s[i]) then
				exit(0);
			result := 10 * result + ord(s[i]) - 48;
		end;
	end;

	procedure SetAuthCookie(AResponse: TResponse; const value: string);
	var
		cookie: TCookie;
	begin
		cookie := AResponse.Cookies.Add;
		cookie.Name := AuthCookieName;
		cookie.Value := value;
		cookie.HttpOnly := True;
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

	function IsAuthorized(ARequest: TRequest): boolean;
	begin
		result := AccountManager.IsAuthorized(GetAuthCookie(ARequest));
	end;

	function GetAuthCookie(ARequest: TRequest): string;
	begin
		result := ARequest.CookieFields.Values[AuthCookieName];
	end;

	function GetQueryUserId(ARequest: TRequest): TUserId;
	begin
		result := StrToQWord(ARequest.QueryFields.Values['userid']);
	end;

	procedure SendUnauthorized(AResponse: TResponse);
	begin
			AResponse.Code := 401;
			AResponse.Content := 'Unauthorized';
	end;

	function GetTemplate(const path: string): string;
	var
		fin: text;
		tmp: string;
		fullPath: string;
	begin
		fullPath := './templates/' + path;
		if not FileExists(fullPath) then
		begin
			writeln(fullPath, 'not found =(');
			exit('!!!fail!!!');
		end;

		assign(fin, fullPath);
		reset(fin);
		result := '';
		while not eof(fin) do
		begin
			readln(fin, tmp);
			result := result + tmp;
		end;
		close(fin);
	end;
end.
