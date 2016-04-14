unit DashboardContainer;

{$mode objfpc}{$H+}
{$modeswitch advancedrecords}

interface
	uses
		fgl, SysUtils, Utils, avglvltree;

	type
		TSensorId = QWord;
		TDashboardId = QWord;

		TDashboardIds = specialize TFPGList<TDashboardId>;
		TSensors = specialize TFPGList<TSensorId>;
		TSensorss = specialize TFPGList<TSensors>;

		TDashboard = record
			Name: string;
			Description: string;
			Sensors: TSensorss;
		end;

		TDashboardPair = record
			ID: string;
			Name: string;
			class operator = (const a, b: TDashboardPair): Boolean;
		end;

		TDashboards = specialize TFPGList<TDashboardPair>;

		TDashboardManager = class(TObject)
			private
				rwSync: TSimpleRWSync;
				saveFile: Text;
				dashboards: TStringToPointerTree;
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

	type
		PDashboard = ^TDashboard;
	
	class operator TDashboardPair.= (const a, b: TDashboardPair): Boolean;
	begin
		result := a.Id = b.Id;
	end;

	procedure TDashboardManager.Initialize;
	var
		filename: string;
		dashboard: PDashboard;
		sensor: TSensorId;
		n, k, i, j: longint;
		dashboardId: string;
	begin
		writeln(stderr, 'Initialize DashboardManager');
		flush(stderr);
		rwSync := TSimpleRWSync.Create;
		dashboards := TStringToPointerTree.Create(true);

		filename := writeDir + 'dashboards';
		assign(saveFile, filename);
		if FileExists(filename) then
		begin
			reset(saveFile);
			while not seekeof(saveFile) do
			begin
				new(dashboard);
				readln(saveFile, dashboardid);
				readln(saveFile, dashboard^.Name);
				readln(saveFile, dashboard^.Description);
				read(saveFile, n);
				dashboard^.Sensors := TSensorss.Create;
				for i := 1 to n do
				begin
					dashboard^.Sensors.Add(TSensors.Create);
					read(saveFile, k);
					for j := 1 to k do
					begin
						read(saveFile, sensor);
						dashboard^.Sensors.last.add(sensor);
					end;
				end;
				readln(saveFile);

				dashboards[dashboardId] := dashboard;
			end;
			append(saveFile);
		end
		else
			rewrite(saveFile);
	end;

	function TDashboardManager.GetDashBoard(const dashboardId: TDashboardId): TDashboard;
	var
		sdashboardid: string;
	begin
		result := EmpyDashboard;
		sdashboardid := inttostr(dashboardId);
		rwSync.beginRead;
		if dashboards.contains(sdashboardid) then
			result := PDashboard(dashboards[sdashboardid])^;
		rwSync.endRead;
	end;
	
	function TDashboardManager.CreateDashboard(const name, description: string): TDashboardId;
	var
		dashboard: PDashboard;
		dashboardid: TDashboardId;
	begin
		new(dashboard);
		dashboardid := GetGuid;
		dashboard^.name := htmlEncode(name);
		dashboard^.description := htmlEncode(description);

		rwSync.beginWrite;
		writeln(saveFile, dashboardid);
		writeln(saveFile, dashboard^.name);
		writeln(saveFile, dashboard^.description);
		writeln(saveFile, 0);
		flush(saveFile);
		dashboards[IntToStr(dashboardId)] := dashboard;
		rwSync.endWrite;

		result := dashboardid;
	end;

	function TDashboardManager.GetDashboards(): TDashboards;
	var
		s2pitem: PStringToPointerItem;
		pair: TDashboardPair;
	begin
		result := TDashboards.Create;
		rwSync.beginRead;
		for s2pitem in dashboards do
		begin
			pair.Id := s2pitem^.Name;
			pair.Name := PDashboard(s2pitem^.Value)^.Name;
			result.add(pair);
		end;
		rwSync.endRead;
	end;

initialization
	writeln(stderr, 'initialization DashboardContainer');
	flush(stderr);
	DashboardManager := TDashboardManager.Create;
	EmpyDashboard.Name := 'undefined';

end.
