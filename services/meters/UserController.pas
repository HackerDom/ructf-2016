unit UserController;

{$mode objfpc}{$H+}

interface

	uses
		httpdefs, fpHTTP, fpWeb, AccountController, WebUtils;

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

	procedure TUserModule.OnLogin(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
	var
		username, password: string;
		userid: int64;
	begin
		GetUsernameAndPassword(ARequest, username, password);
		userId := AccountManager.GetUserId(username, password);
		if userid <> 0 then
			SetAuthCookie(AResponse, userid)
		else
			AResponse.Content := 'username of password is incorrect';
		Handled := True;
	end;

	procedure TUserModule.OnLogout(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
	begin
		ClearAuthCookie(AResponse);
		Handled := True;
	end;

	procedure TUserModule.OnRegister(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
	var
		username, password, message: string;
		userid: int64;
	begin
		GetUsernameAndPassword(ARequest, username, password);
		message := AccountManager.CreateUser(username, password);
		if message = '' then
		begin
			userid := AccountManager.GetUserId(username, password);
			SetAuthCookie(AResponse, userid);
		end;
		AResponse.Content := message;
		Handled := True;
	end;

	procedure TUserModule.OnList(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
	begin
		if not IsAuthorized(ARequest) then
		begin
			SendUnauthorized(AResponse);
			Handled := True;
			exit;
		end;

		AResponse.Content := AccountManager.GetListOfUsers();
		Handled := True;
	end;

initialization
	RegisterHTTPModule('user', TUserModule);
end.

