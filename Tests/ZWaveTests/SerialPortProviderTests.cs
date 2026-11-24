// SPDX-License-Identifier: BSD-3-Clause
// SPDX-FileCopyrightText: Z-Wave Alliance <https://z-wavealliance.org>
using NUnit.Framework;
using ZWave.Layers.Transport;

namespace ZWaveTests
{
    [TestFixture]
    public class SerialPortProviderTests
    {
        [Test]
        public void FilterMacPortNames_KeepsCallOutDevicesOnly()
        {
            var ports = new[]
            {
                "/dev/tty.usbmodem14201", "/dev/tty.Bluetooth-Incoming-Port", "/dev/tty.debug-console",
                "/dev/cu.usbmodem14201", "/dev/cu.Bluetooth-Incoming-Port", "/dev/cu.debug-console",
                "/dev/cu.usbserial-0001", "/dev/cu.usbmodem14201"
            };

            var filtered = SerialPortProvider.FilterMacPortNames(ports);

            CollectionAssert.AreEqual(new[] { "/dev/cu.usbmodem14201", "/dev/cu.usbserial-0001" }, filtered);
        }
    }
}
