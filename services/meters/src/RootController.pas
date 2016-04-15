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

	const
		ModuleName = 'root';

	var
		rootTemplate: string;

	procedure TRootModule.OnRequest(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
	begin
		Handled := True;
		AResponse.Content := StringReplace(rootTemplate, '{-body-}', '', []);
	end;


initialization
	writeln(stderr, 'initialization RootController');
	flush(stderr);
	rootTemplate := GetLayout(ModuleName, 'root');
	RegisterHTTPModule('', TRootModule);

end.
