Name:           gabriel
Version:        0.1.3
Release:        1%{?dist}
Summary:        Gabriel is a DBUS-proxy to connect hosts over DBUS 

License:        GPLv3+
URL:           https://gitea.ladish.org/LADI/gabriel

Source0:       %{name}-%{version}.tar.gz

BuildRequires: dbus automake autoconf gcc glibc-devel libssh-devel glib2-devel
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
* Tue Aug 22 2023 vadik likholetov <vadikas@gmail.com> 0.1.3-1
- Automatic commit of package [gabriel] release [0.1.2-1]. (vadikas@gmail.com)

* Tue Aug 22 2023 vadik likholetov <vadikas@gmail.com> 0.1.2-1
- 

* Tue Aug 22 2023 vadik likholetov <vadikas@gmail.com> 0.1.1-1
- Update gabriel.spec (vadikas@gmail.com)
- Update gabriel.spec (vadikas@gmail.com)

* Tue Aug 22 2023 vadik likholetov <vadikas@gmail.com>
- Update gabriel.spec (vadikas@gmail.com)
- Update gabriel.spec (vadikas@gmail.com)

* Tue Aug 22 2023 vadik likholetov <vadikas@gmail.com> 0.1.0-1
- new package built with tito

* Mon Aug 21 2023 vadik likholetov
- 
