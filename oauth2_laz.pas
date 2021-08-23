{ This file was automatically created by Lazarus. Do not edit!
  This source is only used to compile and install the package.
 }

unit oauth2_laz;

{$warn 5023 off : no warning about unused units}
interface

uses
  oauth2Client, oauth2errors, oauth2tokens, LazarusPackageIntf;

implementation

procedure Register;
begin
  RegisterUnit('oauth2Client', @oauth2Client.Register);
end;

initialization
  RegisterPackage('oauth2_laz', @Register);
end.
