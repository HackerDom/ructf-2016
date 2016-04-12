unit DashboardController;

{$mode objfpc}{$H+}

interface

	uses
		httpdefs, fpHTTP, fpWeb, AccountController, WebUtils, DashboardContainer, Utils, SysUtils;
	
	type
		TDashboardModule = class(TFPWebModule)
			procedure OnMy(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
			procedure OnAll(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
			procedure OnView(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
			procedure OnCreate(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
		end;

implementation

{$R *.lfm}

	const
		ModuleName = 'dashboard';

	var
		listTemplate, listATemplate: string;
		viewTemplate: string;
		createTemplate: string;

	function GetList(const dashboards: TDashboards): string;
	var
		list, tmp: string;
		i: longint;
	begin
		list := '';
		for i := 0 to dashboards.Count - 1 do
		begin
			tmp := StringReplace(listATemplate, '{-dashboardid-}', IntToStr(dashboards[i].Id), []);
			list := list + StringReplace(tmp, '{-dashboard-}', dashboards[i].Name, []);
		end;

		result := StringReplace(listTemplate, '{-list-}', list, []);
	end;

	function GetDashboards(ARequest: TRequest): TDashboards;
	var
		dashboards: TDashboardIds;
		i: longint;
	begin
		dashboards := GetPermittedDashboards(ARequest);
		if dashboards = nil then
			exit(nil);
		result := TDashboards.Create;
		for i := 0 to dashboards.Count - 1 do
			result.add(DashboardManager.GetDashboard(dashboards[i]));
	end;

	procedure TDashboardModule.OnMy(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
	var
		dashboards: TDashboards;
	begin
		Handled := True;

		dashboards := GetDashboards(ARequest);
		if dashboards = nil then
			AResponse.Content := StringReplace(listTemplate, '{-list-}', 'not authorized', [])
		else if dashboards.Count = 0 then
			AResponse.Content := StringReplace(listTemplate, '{-list-}', 'can''t find dashboards for current user', [])
		else
			AResponse.Content := GetList(dashboards);
	end;

	procedure TDashboardModule.OnAll(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
	begin
		Handled := True;
		AResponse.Content := GetList(DashboardManager.GetDashboards);
	end;

	procedure TDashboardModule.OnView(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
	var
		dashboardid: TDashboardId;
		dashboard: TDashboard;
		message: string;
		page: string;
	begin
		dashboardid := GetQueryDashboardId(ARequest);
		dashboard := DashboardManager.GetDashboard(dashboardid);

		page := StringReplace(viewTemplate, '{-name-}', dashboard.Name, []);

		message := HavePermission(ARequest, dashboardid);
		if message <> '' then
		begin
			page := StringReplace(page, '{-description-}', message, []);
			AResponse.Content := StringReplace(page, '{-sensors-}', '', []);
			Handled := True;
			exit;
		end;

		page := StringReplace(page, '{-description-}', dashboard.Description, []);
	
		AResponse.Content := StringReplace(page, '{-sensors-}', 'not implemented', []);
		Handled := True;
	end;

	procedure TDashboardModule.OnCreate(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
	var
		dname, description: string;
		layout, message: string;
		userid: TUserId;
		dashboardId: TDashboardId;
	begin
		Handled := True;
		message := IsAuthorized(ARequest);
		if message <> '' then
		begin
			layout := GetLayout(ModuleName, 'create');
			AResponse.Code := 401; 
			AResponse.Content := StringReplace(layout, '{-body-}', message, []);
			exit;
		end;

		dname := ARequest.ContentFields.Values['name'];
		description := ARequest.ContentFields.Values['description'];

		if (dname = '') and (description = '') then
		begin
			AResponse.Content := StringReplace(createTemplate, '{-message-}', '', []);
			exit;
		end;

		if (dname = '') or (description = '') then
		begin
			AResponse.Content := StringReplace(createTemplate, '{-message-}', 'both name and description are required', []);
			exit;
		end;
		
		if HasBadSymbols(dname) or HasBadSymbols(description) then
		begin
			AResponse.Content := StringReplace(createTemplate, '{-message}', 'name and description must contains symbols with codes from [32 .. 127]', []);
			exit;
		end;

		userId := GetCurrentUserId(ARequest);
		dashboardId := DashboardManager.CreateDashboard(dname, description);
		AccountManager.AddDashboard(userId, dashboardid);
		AddPermission(ARequest, AResponse, dashboardid);

		AResponse.SendRedirect('/dashboard/view/?dashboardId=' + IntToStr(dashboardid));
	end;

initialization
	writeln(stderr, 'initialization DashboardController');
	flush(stderr);
	listTemplate := GetTemplate(ModuleName, 'list');
	listATemplate := GetSubTemplate(ModuleName, 'list.a');
	viewTemplate := GetTemplate(ModuleName, 'view');
	createTemplate := GetTemplate(ModuleName, 'create');
	RegisterHTTPModule(ModuleName, TDashboardModule);

end.
