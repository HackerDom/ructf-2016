unit DashboardController;

{$mode objfpc}{$H+}

interface

	uses
		httpdefs, fpHTTP, fpWeb, AccountController, WebUtils, DashboardContainer, Utils, SysUtils, Sensors;
	
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
		viewTemplate, viewSensorTemplate, viewLineTemplate: string;
		createTemplate: string;

	function GetList(const dashboards: TDashboards; const listName: string): string;
	var
		list, tmp: string;
		i: longint;
	begin
		list := '';
		for i := 0 to dashboards.Count - 1 do
		begin
			tmp := StringReplace(listATemplate, '{-dashboardid-}', dashboards[i].Id, []);
			tmp := StringReplace(tmp, '{-class-}', BoolToStr(dashboards[i].IsPublic, 'public', ''), []);
			list := list + StringReplace(tmp, '{-dashboard-}', dashboards[i].Name, []);
		end;

		result := StringReplace(listTemplate, '{-list-}', list, []);
		result := StringReplace(result, '{-title-}', listName, []);
	end;

	function GetDashboards(ARequest: TRequest): TDashboards;
	var
		dashboards: TDashboardIds;
		dashboard: TDashboard;
		pair: TDashboardPair;
		i: longint;
	begin
		dashboards := GetPermittedDashboards(ARequest);
		if dashboards = nil then
			exit(nil);
		result := TDashboards.Create;
		for i := 0 to dashboards.Count - 1 do
		begin
			dashboard := DashboardManager.GetDashboard(dashboards[i]);
			pair.id := intTostr(dashboards[i]);
			pair.Name := dashboard.Name;
			pair.IsPublic := dashboard.isPublic;
			result.add(pair);
		end;
		dashboards.free;
	end;

	procedure TDashboardModule.OnMy(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
	const
		title = 'My Dasboards';
	var
		dashboards: TDashboards;
		errorTemplate: string;
	begin
		Handled := True;

		dashboards := GetDashboards(ARequest);
		errorTemplate := StringReplace(listTemplate, '{-title-}', title, []);
		if dashboards = nil then
			AResponse.Content := StringReplace(errorTemplate, '{-list-}', 'You must login for view this page', [])
		else if dashboards.Count = 0 then
			AResponse.Content := StringReplace(errorTemplate, '{-list-}', 'can''t find dashboards for current user', [])
		else
			AResponse.Content := GetList(dashboards, title);
		dashboards.free;
	end;

	procedure TDashboardModule.OnAll(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
	var
		dashboards: TDashboards;
	begin
		Handled := True;
		dashboards := DashboardManager.GetDashboards;
		AResponse.Content := GetList(dashboards, 'Dashboards');
		dashboards.Free;
	end;

	procedure TDashboardModule.OnView(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
	var
		dashboardid: TDashboardId;
		dashboard: TDashboard;
		message: string;
		page: string;
		list, line, tmp: string;
		values: TValuess;
		i: longint;
	begin
		Handled := True;
		dashboardid := GetQueryDashboardId(ARequest);
		dashboard := DashboardManager.GetDashboard(dashboardid);

		page := StringReplace(viewTemplate, '{-name-}', dashboard.Name, []);

		if dashboard.IsPublic then
			message := ''
		else
			message := HavePermission(ARequest, dashboardid);
		if message <> '' then
		begin
			page := StringReplace(page, '{-description-}', message, []);
			AResponse.Content := StringReplace(page, '{-sensors-}', '', []);
			exit;
		end;

		page := StringReplace(page, '{-description-}', dashboard.Description, []);


		values := GetSensorsValues(dashboard.sensors);
		line := '';
		list := '';
		for i := 0 to values.Count - 1 do
		begin
			tmp := StringReplace(viewSensorTemplate, '{-data-}', ValuesToString(values[i]), []);
			line := line + StringReplace(tmp, '{-id-}', intToStr(i), [rfReplaceAll]);
			if (i + 1) mod 4 = 0 then
			begin
				list := list + StringReplace(viewLineTemplate, '{-line-}', line, []);
				line := '';
			end;
			values[i].free;
		end;

		values.free;

		if line <> '' then
			list := list + StringReplace(viewLineTemplate, '{-line-}', line, []);

		AResponse.Content := StringReplace(page, '{-sensors-}', list, []);
	end;

	procedure TDashboardModule.OnCreate(Sender: TObject; ARequest: TRequest; AResponse: TResponse; var Handled: Boolean);
	var
		dname, description, isPublic: string;
		layout, message: string;
		userid: TUserId;
		dashboardId: TDashboardId;
		ssensors: string;
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
		isPublic := ARequest.ContentFields.Values['public'];
		ssensors := ARequest.ContentFields.Values['sensors'];

		if (dname = '') and (description = '') and (ssensors = '') then
		begin
			AResponse.Content := StringReplace(createTemplate, '{-message-}', '', []);
			exit;
		end;

		if dname = ''  then
		begin
			AResponse.Content := StringReplace(createTemplate, '{-message-}', 'dashboard name is required', []);
			exit;
		end;
		
		if HasBadSymbols(dname) or HasBadSymbols(description) or HasBadSymbols(ssensors) then
		begin
			AResponse.Content := StringReplace(createTemplate, '{-message-}', 'name, description and configuration must contains symbols with codes from [32 .. 127]', []);
			exit;
		end;

		userId := GetCurrentUserId(ARequest);
		dashboardId := DashboardManager.CreateDashboard(dname, description, isPublic <> '', ParseSensors(ssensors));
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
	viewSensorTemplate := GetSubTemplate(ModuleName, 'view.sensor');
	viewLineTemplate := GetSubTemplate(ModuleName, 'view.line');
	createTemplate := GetTemplate(ModuleName, 'create');
	RegisterHTTPModule(ModuleName, TDashboardModule);

end.
