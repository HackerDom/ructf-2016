unit WebUtils;

{$mode objfpc}{$H+}

interface
	uses
		httpdefs, AccountController;

	procedure SetAuthCookie(AResponse: TResponse; const userid: int64);
	procedure ClearAuthCookie(AResponse: TResponse);
	procedure GetUsernameAndPassword(ARequest: TRequest; var username, password: string);
	procedure SendUnauthorized(AResponse: TResponse);

	function IsAuthorized(ARequest: TRequest): boolean;
	function GetAuthCookie(ARequest: TRequest): string;
	
implementation
	const
		AuthCookieName = 'auth';

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

	procedure SendUnauthorized(AResponse: TResponse);
	begin
			AResponse.Code := 401;
			AResponse.Content := 'Unauthorized';
	end;
end.
