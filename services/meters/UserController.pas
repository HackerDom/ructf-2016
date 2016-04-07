unit UserController;

{$mode objfpc}{$H+}

interface

	uses
		httpdefs, fpHTTP, fpWeb, AccountController, WebUtils, SysUtils;

	type
		TUserModule = class(TFPWebModule)
			procedure OnLogin(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
			procedure OnRegister(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
			procedure OnList(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
		end;

	var
		UserModule: TUserModule;

implementation

{$R *.lfm}
	var
		loginTemplate: string;
		registerTemplate: string;
		listTemplate, listATemplate: string;


	function TryGetUsernameAndPassword(ARequest: TRequest; AResponse: TResponse; var username, password: string; const template: string): Boolean;
	begin
		GetUsernameAndPassword(ARequest, username, password);

		if (username = '') and (password = '') then
		begin
			AResponse.Content := StringReplace(template, '{-message-}', '', [rfReplaceAll]);
			exit(false);
		end;

		if (username = '') or (password = '') then
		begin
			AResponse.Content := StringReplace(template, '{-message-}', 'both username and password are required', [rfReplaceAll]);
			exit(false);
		end;
		
		result := true;
	end;

	procedure TUserModule.OnLogin(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
	var
		username, password: string;
		userid: int64;
	begin
		Handled := True;
		AResponse.ContentType := 'text/html';

		if not TryGetUsernameAndPassword(ARequest, AResponse, username, password, loginTemplate) then
			exit;

		userId := AccountManager.GetUserId(username, password);
		if userid <> 0 then
		begin
			SetAuthCookie(AResponse, userid);
			AResponse.SendRedirect('/dashboards?userid=' + IntToStr(userid));
			exit;
		end;

		AResponse.Content := StringReplace(loginTemplate, '{-message-}', 'username or password is incorrect', [rfReplaceAll]);
	end;

	procedure TUserModule.OnRegister(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
	var
		username, password, message: string;
		userid: TUserId;
	begin
		Handled := True;
		AResponse.ContentType := 'text/html';

		if not TryGetUsernameAndPassword(ARequest, AResponse, username, password, loginTemplate) then
			exit;

		message := AccountManager.CreateUser(username, password);
		if message = '' then
		begin
			userid := AccountManager.GetUserId(username, password);
			SetAuthCookie(AResponse, userid);
		end;

		AResponse.Content := StringReplace(loginTemplate, '{-message-}', message, [rfReplaceAll]);
		Handled := True;
	end;

	procedure TUserModule.OnList(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
	var
		users: TUsers;
		links, tmp: string;
		i: longint;
	begin
		if not IsAuthorized(ARequest) then
		begin
			SendUnauthorized(AResponse);
			Handled := True;
			exit;
		end;


		users := AccountManager.GetListOfUsers();
		links := '';
		for i := 0 to users.Count - 1 do
		begin
			tmp := StringReplace(listATemplate, '{-userid-}', IntToStr(users[i].userid), [rfReplaceAll]);
			links := links + StringReplace(tmp, '{-username-}', users[i].username, [rfReplaceAll]);
		end;

		AResponse.ContentType := 'text/html';
		AResponse.Content := StringReplace(listTemplate, '{-list-}', links, [rfReplaceAll]);
		Handled := True;
	end;

initialization
	RegisterHTTPModule('user', TUserModule);
	loginTemplate := GetTemplate('user/login');
	registerTemplate := GetTemplate('user/register');
	listTemplate := GetTemplate('user/list');
	listATemplate := GetTemplate('user/list.a');

end.

