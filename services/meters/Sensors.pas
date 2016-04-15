unit Sensors;

{$mode objfpc}{$H+}

interface
	
	uses
		fgl, RawSensor, Filters, Utils, SysUtils;

	type
		TSensor = specialize TFPGList<longint>;
		TSensors = specialize TFPGList<TSensor>;
		TValues = specialize TFPGList<double>;
		TValuess = specialize TFPGList<TValues>;

	const
		factorsCount = 4;
	function GetSensorsValues(const sensors: TSensors): TValuess;
	function ValuesToString(const values: TValues): string;
	function ParseSensors(const str: string): TSensors;

implementation

	const
		len = 5 * 60;

	var
		rawSensors: array [0 .. FactorsCount - 1] of TFilter;

	function GetSensorsValues(const sensors: TSensors): TValuess;
	var
		raws: TValuess;
		start, finish: longint;
		i, t, j: longint;
		value: double;
	begin
		finish := tsnow - 1;
		start := finish - len - 1;
		raws := TValuess.Create;
		for i := 0 to FactorsCount - 1 do
			raws.Add(rawSensors[i].GetValues(start, finish));
		result := TValuess.Create;
		for i := 0 to sensors.Count - 1 do
		begin
			result.add(TValues.Create);
			for t := start to finish do
			begin
				value := 0;
				for j := 0 to FactorsCount - 1 do
					value := value + sensors[i][j] * raws[j][t - start];
				result.last.add(value);
			end;
		end;

		for i := 0 to FactorsCount - 1 do
			raws[i].free;
		raws.free;
	end;

	function ValuesToString(const values: TValues): string;
	var
		i: longint;
	begin
		result := '[';
		for i := 0 to values.Count - 1 do
		begin
			result := result + floatToStrF(values[i], ffFixed, 15, 15);
			if i <> values.Count - 1 then
				result := result + ',';
		end;
		result := result + ']';
	end;

	function ParseSensors(const str: string): TSensors;
	var
		sum: longint;
		finished: boolean;
		sensor: TSensor;
		i, j: longint;
	begin
		result := TSensors.Create;
		sum := 0;
		finished := true;

		for i := 1 to FactorsCount do
		begin
			sensor := TSensor.Create;
			for j := 1 to FactorsCount do
			begin
				if i = j then
					sensor.add(1)
				else
					sensor.add(0);
			end;
			result.add(sensor);
		end;

		sensor := TSensor.Create;
		for i := 1 to length(str) do
		begin
			if ('0' <= str[i]) and (str[i] <= '9') then
			begin
				sum := sum * 10 + ord(str[i]) - 48;
				finished := false;
			end
			else
			begin
				if finished then
					continue;
				if sensor.count = FactorsCount then
				begin
					result.Add(sensor);
					sensor := TSensor.Create;
				end;
				sensor.add(sum);
				sum := 0;
				finished := true;
			end;
		end;
		if (not finished) and (sensor.count = FactorsCount - 1) then
			sensor.add(sum);
		if sensor.count = FactorsCount then
			result.Add(sensor);
	end;

initialization
	rawSensors[0] := TCountFilter.Create(RawTickSensor, tsnow);
	rawSensors[1] := TMaxFilter.Create(RawTickSensor, tsnow);
	rawSensors[2] := TCountFilter.Create(RawRandomSensor, tsnow);
	rawSensors[3] := TMaxFilter.Create(RawRandomSensor, tsnow);
end.
