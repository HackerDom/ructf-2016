unit DashboardContainer;

{$mode objfpc}{$H+}

interface

	type
		TSensorId = QWord;

		TSensor = record
			Name: string;
			Id: TSensorId;
		end;
		
		TDashboard = record
			Name: string;
			Description: string;
			Sensors: array of array of TSensor;
		end;

		TDashboardManager = class(TObject)
			public
				procedure Initialize;
				function GetDashBoard()
		end;

implementation

end.
