unit DashboardContainer;

{$mode objfpc}{$H+}
{$modeswitch advancedrecords}

interface
	uses
		fgl, SysUtils, Utils, avglvltree, Sensors;

	type
		TSensorId = QWord;
		TDashboardId = QWord;

		TDashboardIds = specialize TFPGList<TDashboardId>;

		TDashboard = record
			Name: string;
			Description: string;
			IsPublic: boolean;
			Sensors: TSensors;
		end;

		TDashboardPair = record
			ID: string;
			Name: string;
			IsPublic: boolean;
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
				function CreateDashboard(const name, description: string; const ispub: boolean; const sensors: TSensors): TDashboardId;
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
		dashboardId: string;
		ispub: byte;
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
				readln(saveFile, ispub);
				dashboard^.IsPublic := ispub = 1;
				readln(saveFile, dashboard^.sensors);
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
		try
			if dashboards.contains(sdashboardid) then
				result := PDashboard(dashboards[sdashboardid])^;
		finally
			rwSync.endRead;
		end;
	end;
	
	function TDashboardManager.CreateDashboard(const name, description: string; const ispub: boolean; const sensors: TSensors): TDashboardId;
	var
		dashboard: PDashboard;
		dashboardid: TDashboardId;
		oisPub: byte;
	begin
		new(dashboard);
		dashboardid := GetGuid;
		dashboard^.name := htmlEncode(name);
		dashboard^.description := htmlEncode(description);
		dashboard^.isPublic := ispub;
		dashboard^.sensors := sensors;

		rwSync.beginWrite;
		try
			writeln(saveFile, dashboardid);
			writeln(saveFile, dashboard^.name);
			writeln(saveFile, dashboard^.description);
			if dashboard^.IsPublic then
				oisPub := 1
			else
				oisPub := 0;
			writeln(saveFile, oisPub);
			writeln(saveFile, sensors);
			flush(saveFile);
			dashboards[IntToStr(dashboardId)] := dashboard;
		finally
			rwSync.endWrite;
		end;

		result := dashboardid;
	end;

	function TDashboardManager.GetDashboards(): TDashboards;
	var
		s2pitem: PStringToPointerItem;
		pair: TDashboardPair;
	begin
		result := TDashboards.Create;
		rwSync.beginRead;
		try
			for s2pitem in dashboards do
			begin
				pair.Id := s2pitem^.Name;
				pair.Name := PDashboard(s2pitem^.Value)^.Name;
				pair.IsPublic := PDashboard(s2pitem^.Value)^.IsPublic;
				result.add(pair);
			end;
		finally
			rwSync.endRead;
		end;
	end;

initialization
	writeln(stderr, 'initialization DashboardContainer');
	flush(stderr);
	DashboardManager := TDashboardManager.Create;
	EmpyDashboard.Name := 'undefined';

end.
