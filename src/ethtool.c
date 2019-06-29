#include <rte_version.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_bus_pci.h>
#include <linux/ethtool.h>

int rte_ethtool_get_drvinfo(uint16_t port_id, struct ethtool_drvinfo *drvinfo);

int rte_ethtool_get_drvinfo(uint16_t port_id, struct ethtool_drvinfo *drvinfo)
{
	struct rte_eth_dev_info dev_info;
	struct rte_dev_reg_info reg_info;
	const struct rte_pci_device *pci_dev;
	const struct rte_bus *bus = NULL;
	int n;

	if (drvinfo == NULL)
		return -EINVAL;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port_id, -ENODEV);
				  
	#ifdef _DP_DBG
	int ret = rte_eth_dev_fw_version_get(port_id, drvinfo->fw_version,
			      sizeof(drvinfo->fw_version));
	if (ret < 0)
		printf("firmware version get error: (%s)\n", strerror(-ret));
	else if (ret > 0)
		printf("Insufficient fw version buffer size, "
		       "the minimum size should be %d\n", ret);
	#endif

	memset(&dev_info, 0, sizeof(dev_info));
	rte_eth_dev_info_get(port_id, &dev_info);

	snprintf(drvinfo->driver, sizeof(drvinfo->driver), "%s",
		dev_info.driver_name);
	snprintf(drvinfo->version, sizeof(drvinfo->version), "%s",
		rte_version());
	if (dev_info.device)
		bus = rte_bus_find_by_device(dev_info.device);
	if (bus && !strcmp(bus->name, "pci")) {
		pci_dev = RTE_DEV_TO_PCI(dev_info.device);
		snprintf(drvinfo->bus_info, sizeof(drvinfo->bus_info),
			"%04x:%02x:%02x.%x",
			pci_dev->addr.domain, pci_dev->addr.bus,
			pci_dev->addr.devid, pci_dev->addr.function);
	} 
	else
		snprintf(drvinfo->bus_info, sizeof(drvinfo->bus_info), "N/A");

	memset(&reg_info, 0, sizeof(reg_info));
	rte_eth_dev_get_reg_info(port_id, &reg_info);
	n = reg_info.length;
	if (n > 0)
		drvinfo->regdump_len = n;
	else
		drvinfo->regdump_len = 0;

	n = rte_eth_dev_get_eeprom_length(port_id);
	if (n > 0)
		drvinfo->eedump_len = n;
	else
		drvinfo->eedump_len = 0;

	drvinfo->n_stats = sizeof(struct rte_eth_stats) / sizeof(uint64_t);
	drvinfo->testinfo_len = 0;

	return 0;
}