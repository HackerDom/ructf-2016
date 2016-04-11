unit DashboardController;

{$mode objfpc}{$H+}

interface

	uses
		httpdefs, fpHTTP, fpWeb, AccountController, WebUtils, DashboardContainer, Utils, SysUtils;
	
	type
		TDashboardModule = class(TFPWebModule)
			procedure OnList(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
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

	procedure TDashboardModule.OnList(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
	var
		userid: TUserId;
		user: TUser;
		dashboards: TDashboards;
		dashboard: TDashboard;
		list, tmp: string;
		i: longint;
	begin
		Handled := True;

		userid := GetQueryUserId(ARequest);
		if userid = 0 then
			userId := GetCurrentUserId(ARequest);
		if userid = 0 then
		begin
			AResponse.Code := 400;
			AResponse.Content := StringReplace(listTemplate, '{-list-}', 'can''t find any user in query', []);
			exit;
		end;

		dashboards := AccountManager.GetDashboards(userid);
		if dashboards = nil then
		begin
			user := AccountManager.GetUser(userid);
			AResponse.Content := StringReplace(listTemplate, '{-list-}', 'can''t find dashboards for user ' + user.username, []);
			exit;
		end;

		list := '';
		for i := 0 to dashboards.Count - 1 do
		begin
			dashboard := DashboardManager.GetDashboard(dashboards[i]);
			tmp := StringReplace(listATemplate, '{-dashboardid-}', IntToStr(dashboards[i]), []);
			list := list + StringReplace(tmp, '{-dashboard-}', dashboard.Name, []);
		end;

		AResponse.Content := StringReplace(listTemplate, '{-list-}', list, []);
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
		layout: string;
		userid: TUserId;
		dashboardId: TDashboardId;
	begin
		Handled := True;
		if not IsAuthorized(ARequest) then
		begin
			layout := GetLayout(ModuleName, 'create');
			AResponse.Code := 401; 
			AResponse.Content := StringReplace(layout, '{-body-}', 'login before can create', []);
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

		AResponse.SendRedirect('/dashboard/view?dashboardId=' + IntToStr(dashboardid));
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
