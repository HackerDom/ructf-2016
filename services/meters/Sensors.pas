unit Sensors;

{$mode objfpc}{$H+}

interface
	
	uses
		fgl, RawSensor, Filters, Utils, SysUtils;

	type
		TSensors = string;
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
		start, finish: longint;
		i, t, j: longint;
		value: double;
	begin
		finish := tsnow - 1;
		start := finish - len + 1;
		result := TValuess.Create;
		for i := 0 to FactorsCount - 1 do
			result.Add(rawSensors[i].GetValues(start, finish));
		for i := 0 to length(sensors) div FactorsCount - 1 do
		begin
			result.add(TValues.Create);
			for t := start to finish do
			begin
				value := 0;
				for j := 1 to FactorsCount do
					value := value + ord(sensors[4 * i + j]) * result[j - 1][t - start];
				result.last.add(value);
			end;
		end;
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
	begin
		result := str;
		while length(result) mod FactorsCount <> 0 do
			result := result + ' ';
	end;

initialization
	rawSensors[0] := TCountFilter.Create(RawTickSensor, tsnow);
	rawSensors[1] := TMaxFilter.Create(RawTickSensor, tsnow);
	rawSensors[2] := TCountFilter.Create(RawRandomSensor, tsnow);
	rawSensors[3] := TMaxFilter.Create(RawRandomSensor, tsnow);
end.
