program httpproject1;

{$mode objfpc}{$H+}

uses
	cthreads, fphttpapp, fpWebFile, UserController, AccountController, DashboardController, Sensor;


{
procedure StartSensors;
begin
	RawTickSensor.Initialize;
	BeginThread(@RawTickSensor.Run);
end;
}

begin
	Application.Title := 'meters';
	Application.Port := 6725;
	Application.Threaded := True;
	Application.QueueSize := 100;
	Application.Initialize;
	AccountManager.Initialize;

//	StartSensors;

	RegisterFileLocation('js', 'js');
	RegisterFileLocation('css', 'css');
	MimeTypesFile := '/etc/mime.types';

	Application.Run;
end.
