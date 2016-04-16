unit RootController;

{$mode objfpc}{$H+}

interface

	uses
		httpdefs, fpHTTP, fpWeb, Utils, SysUtils;
	
	type
		TRootModule = class(TFPWebModule)
			procedure OnRequest(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
		end;

implementation

{$R *.lfm}

	procedure TRootModule.OnRequest(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
	begin
		Handled := True;
		AResponse.SendRedirect('/user/login/');
	end;

end.
