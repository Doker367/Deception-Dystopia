# Despliegue soportado

Ubuntu Server 24.04 LTS, KVM/libvirt. Consulte la [guía de instalación y operación](<docs/HARDENING-OPERATIONS.md>), [ejemplo sintético](<deploy/install.example.json>) y [unidades systemd](<deploy/systemd/dystopia-control.service>).

El instalador empieza en plan, no descarga paquetes ni modifica redes. Apply necesita root local, confirmación explícita, interfaces/redes indicadas, recuperación, bundle offline con lock/hash completos y release/venv revisados. Arranca únicamente gestión en loopback después del alta local del primer administrador.

Sensores, adaptadores heredados y activación de VMs no se habilitan automáticamente. No hay contención real verificada ni bundle final certificado en esta entrega. [Pruebas y bloqueos](<docs/HARDENING-TESTS.md>).
