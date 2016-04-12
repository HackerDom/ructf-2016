unit DashboardContainer;

{$mode objfpc}{$H+}
{$modeswitch advancedrecords}

interface
	uses
		fgl, SysUtils, Utils;

	type
		TSensorId = QWord;
		TDashboardId = QWord;

		TDashboardIds = specialize TFPGList<TDashboardId>;
		TSensors = specialize TFPGList<TSensorId>;
		TSensorss = specialize TFPGList<TSensors>;

		TDashboard = record
			ID: TDashboardId;
			Name: string;
			Description: string;
			Sensors: TSensorss;
			class operator = (const a, b: TDashboard): Boolean;
		end;

		TDashboards = specialize TFPGList<TDashboard>;

		TDashboardManager = class(TObject)
			private
				rwSync: TSimpleRWSync;
				saveFile: Text;
				dashboards: TDashboards;
			public
				procedure Initialize;
				function GetDashBoard(const dashboardId: TDashboardId): TDashboard;
				function CreateDashboard(const name, description: string): TDashboardId;
				function GetDashboards(): TDashboards;
		end;

	var
		DashboardManager: TDashboardManager;
		EmpyDashboard: TDashboard;

implementation
	
	class operator TDashboard.= (const a, b: TDashboard): Boolean;
	begin
		result := a.ID = b.ID;
	end;

	procedure TDashboardManager.Initialize;
	var
		filename: string;
		dashboard: TDashboard;
		sensor: TSensorId;
		n, k, i, j: longint;
	begin
		writeln(stderr, 'Initialize DashboardManager');
		flush(stderr);
		rwSync := TSimpleRWSync.Create;
		dashboards := TDashboards.Create;

		filename := writeDir + 'dashboards';
		assign(saveFile, filename);
		if FileExists(filename) then
		begin
			reset(saveFile);
			while not seekeof(saveFile) do
			begin
				readln(saveFile, dashboard.ID);
				readln(saveFile, dashboard.Name);
				readln(saveFile, dashboard.Description);
				read(saveFile, n);
				dashboard.Sensors := TSensorss.Create;
				for i := 1 to n do
				begin
					dashboard.Sensors.Add(TSensors.Create);
					read(saveFile, k);
					for j := 1 to k do
					begin
						read(saveFile, sensor);
						dashboard.Sensors.last.add(sensor);
					end;
				end;

				dashboards.add(dashboard);
			end;
			append(saveFile);
		end
		else
			rewrite(saveFile);
	end;

	function TDashboardManager.GetDashBoard(const dashboardId: TDashboardId): TDashboard;
	var
		i: longint;
	begin
		result := EmpyDashboard;
		rwSync.beginRead;
			for i := 0 to dashboards.Count - 1 do
				if dashboards[i].Id = dashboardId then
				begin
					result := dashboards[i];
					break;
				end;
		rwSync.endRead;
	end;
	
	function TDashboardManager.CreateDashboard(const name, description: string): TDashboardId;
	var
		dashboard: TDashboard;
	begin
		dashboard.ID := GetGuid;
		dashboard.name := htmlEncode(name);
		dashboard.description := htmlEncode(description);

		rwSync.beginWrite;
		writeln(saveFile, dashboard.Id);
		writeln(saveFile, dashboard.name);
		writeln(saveFile, dashboard.description);
		writeln(saveFile, 0);
		flush(saveFile);
		dashboards.Add(dashboard);
		rwSync.endWrite;

		result := dashboard.ID;
	end;

	function TDashboardManager.GetDashboards(): TDashboards;
	begin
		result := TDashboards.Create;
		result.assign(dashboards);
	end;

initialization
	writeln(stderr, 'initialization DashboardContainer');
	flush(stderr);
	DashboardManager := TDashboardManager.Create;
	EmpyDashboard.Id := 0;
	EmpyDashboard.Name := 'undefined';

end.
