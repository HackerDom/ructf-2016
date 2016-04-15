!
version 12.2
no service pad
service timestamps debug datetime msec
service timestamps log datetime msec
no service password-encryption
!
hostname olymp-core-sw
!
boot-start-marker
boot-end-marker
!
enable secret 5 $1$4QRf$csWRzF07DszrBId3q3iRz1
!
username root privilege 15 secret 5 $1$H23W$zBTH0mhH4mnPlEo3yyY7V/
aaa new-model
!
!
!
!
!
aaa session-id common
system mtu routing 1500
vtp mode transparent
ip subnet-zero
no ip domain-lookup
ip domain-name ussc.ru
!
!
!
!
crypto pki trustpoint TP-self-signed-3613081472
 enrollment selfsigned
 subject-name cn=IOS-Self-Signed-Certificate-3613081472
 revocation-check none
 rsakeypair TP-self-signed-3613081472
!
!
crypto pki certificate chain TP-self-signed-3613081472
 certificate self-signed 01
  30820245 308201AE A0030201 02020101 300D0609 2A864886 F70D0101 04050030 
  31312F30 2D060355 04031326 494F532D 53656C66 2D536967 6E65642D 43657274 
  69666963 6174652D 33363133 30383134 3732301E 170D3933 30333031 30303030 
  35355A17 0D323030 31303130 30303030 305A3031 312F302D 06035504 03132649 
  4F532D53 656C662D 5369676E 65642D43 65727469 66696361 74652D33 36313330 
  38313437 3230819F 300D0609 2A864886 F70D0101 01050003 818D0030 81890281 
  8100D9BF A72070D4 2BC971D6 D708850E BB66C8CB 37ECE5E6 C4435724 19B25AAF 
  12DBC92F D6FDB336 15465992 29DDFB77 C55CDDE7 0262BAC7 79D75B1F A3EF0B37 
  85C06EC7 79BEAE85 66CAAA9C B5673436 5FA44377 E4F78AFB 244EBD72 7AEEBAF2 
  1B23C1D1 BDC3DF6A F21F1859 14F5B725 B097F28C 85AD2DBE 27E38D03 AF324444 
  841B0203 010001A3 6D306B30 0F060355 1D130101 FF040530 030101FF 30180603 
  551D1104 11300F82 0D436973 636F2E75 7373632E 7275301F 0603551D 23041830 
  16801447 4AE8283F 7F1C93F3 AD62C6AC 9963DB36 14C24530 1D060355 1D0E0416 
  0414474A E8283F7F 1C93F3AD 62C6AC99 63DB3614 C245300D 06092A86 4886F70D 
  01010405 00038181 0010720A 91B9254D 6675237D 80C9B2AA 947BB3E0 AA239E08 
  8CD2D42E 9D6A6C56 48E237DF 8930AF87 A895383B B9980C3D 4E92944B 8BC04950 
  DF5D5529 CE9BDD23 E26B6B70 FB56D7FB 2EF10502 2947761A E2D44E4C B6E5632D 
  16677006 750778AB 9010E5C3 27A43A22 E6112020 0E656CDE B73B64E9 CBA57039 
  4AF6D00A 41EEF7B5 EA
  quit
!
!
!
!
!
!
spanning-tree mode rapid-pvst
spanning-tree extend system-id
spanning-tree vlan 1-1000 priority 61440
!
vlan internal allocation policy ascending
!
vlan 11
 name OLYMP-1
!
vlan 12
 name OLYMP-2
!
vlan 13
 name OLYMP-3
!
vlan 14
 name OLYMP-4
!
vlan 20
 name MGMT
!
vlan 30
 name JURY
!
vlan 40
 name UPLINK
!
vlan 101-199 
!
!
!
!
interface FastEthernet0/1
 description OLYMP-1
 switchport access vlan 11
 switchport mode access
 spanning-tree portfast
!
interface FastEthernet0/2
 description OLYMP-2
 switchport access vlan 12
 switchport mode access
 spanning-tree portfast
!
interface FastEthernet0/3
 description OLYMP-3
 switchport access vlan 13
 switchport mode access
 spanning-tree portfast
!
interface FastEthernet0/4
 description OLYMP-4
 switchport access vlan 14
 switchport mode access
 spanning-tree portfast
!
interface FastEthernet0/5
 description Qoala
 power inline never
 switchport access vlan 30
 switchport mode access
 spanning-tree portfast
!
interface FastEthernet0/6
 description Olymp-win
 power inline never
 switchport access vlan 30
 switchport mode access
 spanning-tree portfast
!
interface FastEthernet0/7
 description Switches
 power inline never
 switchport trunk encapsulation dot1q
 switchport trunk allowed vlan 20,101-199
 switchport mode trunk
 spanning-tree portfast
!
interface FastEthernet0/8
 description UPLINK
 power inline never
 switchport access vlan 40
 switchport mode access
 spanning-tree portfast
!
interface GigabitEthernet0/1
 description ROUTER
 switchport trunk encapsulation dot1q
 switchport trunk allowed vlan 1-999
 switchport mode trunk
!
interface Vlan1
 no ip address
!
interface Vlan20
 ip address 10.0.20.5 255.255.255.0
!
ip classless
ip http server
ip http secure-server
!
!
!
control-plane
!
!
line con 0
line vty 0 4
 transport input ssh
line vty 5 15
 transport input ssh
!
end

