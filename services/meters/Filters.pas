unit Filters;

{$mode objfpc}{$H+}

interface
	uses RawSensor, fgl, SysUtils;

	type
		TValues = specialize TFPGList<double>;

		TFilter = class abstract(TObject)
			protected
				sensor: TRawSensor;
				lastUpdate: longint;
				startTime: longint;
				values: TValues;
				rwSync: TSimpleRWSync;
			public
				constructor Create(const rawsensor: TRawSensor; const start: longint);
				function GetValues(const start, finish: longint): TValues;
				function HandleSecond(const rawValues: TRawValues): double; virtual; abstract;
		end;

		TCountFilter = class(TFilter)
			public
				function HandleSecond(const rawValues: TRawValues): double; override;
		end;

		TMaxFilter = class(TFilter)
			public
				function HandleSecond(const rawValues: TRawValues): double; override;
		end;

implementation	

	constructor TFilter.Create(const rawsensor: TRawSensor; const start: longint);
	begin
		sensor := rawsensor;
		lastUpdate := start;
		startTime := start;
		values := TValues.Create;
		rwSync := TSimpleRWSync.Create;
	end;

	function TFilter.GetValues(const start, finish: longint): TValues;
	var
		data, curData: TRawValues;
		i: longint;
		timestamp, curSecond: int64;
	begin
		if lastUpdate < finish then
		begin
			rwSync.beginWrite;
			if lastUpdate < finish then
			begin
				for i := lastUpdate to finish + 1 do
					values.add(0);
			
				data := sensor.GetValues(lastUpdate, finish);
				curSecond := -1;
				curData := TRawValues.Create;
				for i := 0 to data.count - 1 do
				begin
					timestamp := data[i].timestamp;
					if (timestamp <> curSecond) and (curSecond <> -1) then
					begin
						values[curSecond - startTime] := HandleSecond(curData);
						curData.Clear;
					end;
					curData.Add(data[i]);
					curSecond := timestamp;
				end;
				if curData.Count <> 0 then
					values[curSecond - startTime] := HandleSecond(curData);
			
				lastUpdate := finish;
			end;
			rwSync.EndWrite;
		end;

		result := TValues.Create;
		rwSync.BeginRead;
		for i := start to finish do
			if i < startTime then
				result.add(0)
			else
				result.add(values[i - startTime]);
		rwSync.EndWrite;
	end;

	function TCountFilter.HandleSecond(const rawValues: TRawValues): double;
	begin
		result := rawValues.Count;
	end;

	function TMaxFilter.HandleSecond(const rawValues: TRawValues): double;
	var
		i: longint;
	begin
		if rawValues.Count = 0 then
			exit(0);
		result := rawValues[0].value;
		for i := 1 to rawValues.Count - 1 do
			if result < rawValues[i].value then
				result := rawValues[i].value;
	end;
end.
