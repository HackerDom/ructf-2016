unit Filters;

{$mode objfpc}{$H+}

interface
	uses Sensor, fgl, SysUtils;

	type
		TValues = specialize TFPGList<single>;

		TRawListener = class abstract(TObject)
			protected
				sensor: TRawSensor;
				lastUpdate: longint;
				startTime: longint;
				values: TValues;
				rwSync: TSimpleRWSync;
			public
				constructor Create(const rawsensor: TRawSensor; const start: longint);
				function GetValues(const start, finish: longint): TValues;
				function HandleSecond(const rawValues: TRawValues): single; virtual; abstract;
		end;

		TRawCount = class(TRawListener)
			public
				function HandleSecond(const rawValues: TRawValues): single; override;
		end;

		TRawMax = class(TRawListener)
			public
				function HandleSecond(const rawValues: TRawValues): single; override;
		end;

implementation	

	constructor TRawListener.Create(const rawsensor: TRawSensor; const start: int64);
	begin
		sensor := rawsensor;
		lastUpdate := start;
		startTime := start;
		values := TValues.Create;
		rwSync := TSimpleRWSync.Create;
	end;

	function TRawListener.GetValues(const start, finish: int64): TValues;
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
				for i := lastUpdate to finish do
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
			result.add(values[i]);
		rwSync.EndWrite;
	end;

	function TRawCount.HandleSecond(const rawValues: TRawValues): single;
	begin
		result := rawValues.Count;
	end;

	function TRawMax.HandleSecond(const rawValues: TRawValues): single;
	begin
		if rawValues.Count = 0 then
			exit(0);
		result := rawValues[0];
		for i := 1 to rawValues.Count - 1 do
			if result < rawValues[i] then
				result := rawValues[i];
	end;
end.
