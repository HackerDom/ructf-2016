unit DashboardController;

{$mode objfpc}{$H+}

interface

	uses
		httpdefs, fpHTTP, fpWeb, AccountController, WebUtils;
	
	type
		TDashboardModule = class(TFPWebModule)
			procedure OnList(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
			procedure OnView(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
			procedure OnCreate(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
		end;

	var
		DashboardModule: TDashboardModule;

implementation

{$R *.lfm}

	procedure TDashboardModule.OnList(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
	var
		userid: TUserId;
//		dashboards: 
	begin
		Handled := True;
		userid := GetQueryUserId(ARequest);
		if userid = 0 then
			userId := GetCurrentUserId(ARequest);
		if userid = 0 then
		begin
			AResponse.Content := 'bad request';
			AResponse.Code := 400;
			exit;
		end;
		AResponse.Content := AccountController.GetDashboards(userid);
	end;

	procedure TDashboardModule.OnView(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
	var
		dashboardid: int64;
	begin
		if not HavePermission(ARequest, dashboardid) then
		begin
			SendUnauthorized(AResponse);
			Handled := True;
			exit;
		end;

		AResponse.Content := DashboardContainer.GetDashboard(dashboardid);
	end;

	procedure TDashboardModule.OnCreate(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
	begin
		if not IsAuthorized(ARequest) then
		begin
			SendUnauthorized(AResponse);
			Handled := True;
			exit;
		end;

		
	end;

initialization
	RegisterHTTPModule('dashboard', TDashboardModule);

end.
