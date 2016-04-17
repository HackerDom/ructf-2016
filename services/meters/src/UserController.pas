unit UserController;

{$mode objfpc}{$H+}

interface

	uses
		httpdefs, fpHTTP, fpWeb, AccountController, WebUtils, SysUtils, Utils;

	type
		TUserModule = class(TFPWebModule)
			procedure OnLogin(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
			procedure OnLogout(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
			procedure OnRegister(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
		end;

	var
		UserModule: TUserModule;

implementation

{$R *.lfm}
	const
		ModuleName = 'user';
		maxQuerySize = 256;

	var
		loginTemplate: string;
		registerTemplate: string;

	function TryGetUsernameAndPassword(ARequest: TRequest; AResponse: TResponse; var username, password: string; const template: string): Boolean;
	begin
		GetUsernameAndPassword(ARequest, username, password);

		if (username = '') and (password = '') then
		begin
			AResponse.Content := StringReplace(template, '{-message-}', '', []);
			exit(false);
		end;

		if (username = '') or (password = '') then
		begin
			AResponse.Code := 400;
			AResponse.Content := StringReplace(template, '{-message-}', 'both username and password are required', []);
			exit(false);
		end;

		if (length(username) > maxQuerySize) or (length(password) > maxQuerySize) then
		begin
			AResponse.Code := 400;
			AResponse.Content := StringReplace(template, '{-message-}', format('query is too long, length should not exceed %d bytes', [maxQuerySize]), []);
			exit(false);
		end;

		username := lowercase(username);
		
		result := true;
	end;

	procedure TUserModule.OnLogin(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
	var
		username, password: string;
		userid: TUserId;
	begin

		if not TryGetUsernameAndPassword(ARequest, AResponse, username, password, loginTemplate) then
		begin
			Handled := True;
			exit;
		end;

		userId := AccountManager.GetUserId(username, password);
		if userid <> 0 then
		begin
			SetAuthCookie(AResponse, userid);
			AResponse.SendRedirect('/dashboard/my/');
			Handled := True;
			exit;
		end;

		AResponse.Content := StringReplace(loginTemplate, '{-message-}', 'username or password is incorrect', []);
		AResponse.Code := 400;
		Handled := True;
	end;

	procedure TUserModule.OnLogout(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
	begin
		ClearAuthCookie(AResponse);
		AResponse.SendRedirect('/user/login/');
		Handled := True;
	end;

	procedure TUserModule.OnRegister(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
	var
		username, password, message: string;
		userid: TUserId;
	begin
		if not TryGetUsernameAndPassword(ARequest, AResponse, username, password, registerTemplate) then
		begin
			Handled := True;
			exit;
		end;

		message := AccountManager.CreateUser(username, password);
		if message = '' then
		begin
			userid := AccountManager.GetUserId(username, password);
			SetAuthCookie(AResponse, userid);
			AResponse.SendRedirect('/dashboard/my/');
			Handled := True;
			exit;
		end;

		AResponse.Content := StringReplace(registerTemplate, '{-message-}', message, []);
		AResponse.Code := 400;
		Handled := true;
	end;

initialization
	writeln(stderr, 'initialization UserController');
	flush(stderr);
	loginTemplate := GetTemplate(ModuleName, 'login');
	registerTemplate := GetTemplate(ModuleName, 'register');
	RegisterHTTPModule(ModuleName, TUserModule);

end.

