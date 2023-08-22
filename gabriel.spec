Name:           gabriel
Version:        0.1
Release:        1%{?dist}
Summary:        Gabriel is a DBUS-proxy to connect hosts over DBUS 

License:        GPLv3+
URL:           https://gitea.ladish.org/LADI/gabriel
Source0:       https://github.com/vadika/gabriel/archive/refs/tags/gabriel-0.1.tar.gz

BuildRequires: dbus automake autoconf
Requires: dbus      

%description


%prep
%autosetup


%build
./autogen.sh
%configure
%make_build


%install
%make_install


%files
#%license none
%doc NEWS INSTALL TODO README AUTHORS
/usr/bin/gabriel



%changelog
* Mon Aug 21 2023 vadik likholetov
- 
