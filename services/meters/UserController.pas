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
			procedure OnList(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
		end;

	var
		UserModule: TUserModule;

implementation

{$R *.lfm}
	const
		ModuleName = 'user';

	var
		loginTemplate: string;
		registerTemplate: string;
		listTemplate, listATemplate: string;

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
			AResponse.Content := StringReplace(template, '{-message-}', 'both username and password are required', []);
			exit(false);
		end;
		
		result := true;
	end;

	procedure TUserModule.OnLogin(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
	var
		username, password: string;
		userid: TUserId;
	begin
		Handled := True;

		if not TryGetUsernameAndPassword(ARequest, AResponse, username, password, loginTemplate) then
			exit;

		userId := AccountManager.GetUserId(username, password);
		if userid <> 0 then
		begin
			SetAuthCookie(AResponse, userid);
			AResponse.SendRedirect('/dashboard/list');
			exit;
		end;

		AResponse.Content := StringReplace(loginTemplate, '{-message-}', 'username or password is incorrect', []);
	end;

	procedure TUserModule.OnLogout(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
	begin
		ClearAuthCookie(AResponse);
		AResponse.SendRedirect('/user/login');
		Handled := True;
	end;

	procedure TUserModule.OnRegister(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
	var
		username, password, message: string;
		userid: TUserId;
	begin
		Handled := True;
		AResponse.ContentType := 'text/html';

		if not TryGetUsernameAndPassword(ARequest, AResponse, username, password, registerTemplate) then
			exit;

		message := AccountManager.CreateUser(username, password);
		if message = '' then
		begin
			userid := AccountManager.GetUserId(username, password);
			SetAuthCookie(AResponse, userid);
		end;

		AResponse.Content := StringReplace(registerTemplate, '{-message-}', message, []);
	end;

	procedure TUserModule.OnList(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
	var
		users: TUsers;
		links, tmp: string;
		i: longint;
	begin
		users := AccountManager.GetListOfUsers();
		links := '';
		for i := 0 to users.Count - 1 do
		begin
			tmp := StringReplace(listATemplate, '{-userid-}', IntToStr(users[i].userid), []);
			links := links + StringReplace(tmp, '{-username-}', users[i].username, []);
		end;

		AResponse.ContentType := 'text/html';
		AResponse.Content := StringReplace(listTemplate, '{-list-}', links, []);
		Handled := True;
	end;

initialization
	writeln(stderr, 'initialization UserController');
	flush(stderr);
	loginTemplate := GetTemplate(ModuleName, 'login');
	registerTemplate := GetTemplate(ModuleName, 'register');
	listTemplate := GetTemplate(ModuleName, 'list');
	listATemplate := GetSubTemplate(ModuleName, 'list.a');
	RegisterHTTPModule(ModuleName, TUserModule);

end.

