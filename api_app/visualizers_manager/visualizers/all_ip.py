from logging import getLogger
from typing import Dict, List

from api_app.analyzers_manager.models import AnalyzerReport
from api_app.choices import ReportStatus
from api_app.visualizers_manager.classes import Visualizer
from api_app.visualizers_manager.decorators import (
    visualizable_error_handler_with_params,
)
from api_app.visualizers_manager.enums import (
    VisualizableColor,
    VisualizableIcon,
    VisualizableSize,
)

logger = getLogger(__name__)


class IPReputationServices(Visualizer):
    #to get the IP address
    @visualizable_error_handler_with_params("FileScan_Search")
    def get_ip(self):
        try:
            self.analyzer_report = self.analyzer_reports().get(
                config__name="FileScan_Search"
            )
        except AnalyzerReport.DoesNotExist:
            logger.warning("FileScan_Search report does not exist")
        else:
            message = self.analyzer_report.status
            self.hits = (
                self.analyzer_report.report.get("mdcloud", {})
                .get("detected", 0)
            )
            self.ip_filescan = self.analyzer_report.report.get("ioc_value", "")

        return self.ip_filescan

    @visualizable_error_handler_with_params("ThreatFox")
    def _threatfox(self):
        try:
            analyzer_report = self.analyzer_reports().get(config__name="ThreatFox")
        except AnalyzerReport.DoesNotExist:
            logger.warning("Threatfox report does not exist")
        else:
            disabled = (
                analyzer_report.status != ReportStatus.SUCCESS
                or analyzer_report.report.get("query_status", None) != "ok"
            )
            data = analyzer_report.report.get("data", [])
            malware_printable = ""
            if data and isinstance(data, list):
                malware_printable = data[0].get("malware_printable", "")
            threatfox_report = self.Title(
                self.Base(
                    value="ThreatFox", link=analyzer_report.report.get("link", "")
                ),
                self.Base(value="" if disabled else f"found {malware_printable}"),
                disable=disabled,
            )
            return threatfox_report

    @visualizable_error_handler_with_params("AbuseIPDB Categories")
    def _abuse_ipdb(self):
        try:
            analyzer_report = self.analyzer_reports().get(config__name="AbuseIPDB")
        except AnalyzerReport.DoesNotExist:
            logger.warning("AbuseIPDB report does not exist")
            return None, None
        else:
            data = analyzer_report.report.get("data", [])
            isp = data.get("isp", "")
            usage = data.get("usageType", "")
            disabled = analyzer_report.status != ReportStatus.SUCCESS or (
                not isp and not usage
            )
            abuse_report = self.Title(
                self.Base(
                    value="AbuseIPDB Meta",
                    link=analyzer_report.report.get("permalink", ""),
                    icon=VisualizableIcon.INFO,
                ),
                self.Base(value="" if disabled else f"{isp} ({usage})"),
                disable=disabled,
            )

            categories_extracted = []
            for c in data.get("reports", []):
                categories_extracted.extend(c.get("categories_human_readable", []))
            categories_extracted = list(set(categories_extracted))
            disabled = (
                analyzer_report.status != ReportStatus.SUCCESS
                or not categories_extracted
            )
            abuse_categories_report = self.VList(
                name=self.Base(
                    value="AbuseIPDB Categories",
                    icon=VisualizableIcon.ALARM,
                    color=VisualizableColor.DANGER,
                    disable=disabled,
                ),
                value=[self.Base(c, disable=disabled) for c in categories_extracted],
                start_open=True,
                max_elements_number=5,
                report=analyzer_report,
                disable=disabled,
                size=VisualizableSize.S_2,
            )

            return abuse_report, abuse_categories_report

    @visualizable_error_handler_with_params(
        "Crowdsec Classifications", "Crowdsec Behaviors"
    )
    def _crowdsec(self):
        try:
            analyzer_report = self.analyzer_reports().get(config__name="Crowdsec")
        except AnalyzerReport.DoesNotExist:
            logger.warning("Crowdsec report does not exist")
            return None, None
        else:
            message = analyzer_report.status
            classifications = analyzer_report.report.get("classifications", {})
            sub_classifications = classifications.get("classifications", [])
            false_positives = classifications.get("false_positives", [])
            all_class = sub_classifications + false_positives
            disabled = analyzer_report.status != ReportStatus.SUCCESS or not all_class or message != "SUCCESS"
            crowdsec_classification_report = self.VList(
                name=self.Base(
                    value="Crowdsec Classifications",
                    icon=VisualizableIcon.INFO,
                    color=VisualizableColor.INFO,
                    disable=disabled,
                ),
                value=[
                    self.Base(c.get("label", ""), disable=disabled) for c in all_class
                ],
                start_open=True,
                max_elements_number=5,
                report=analyzer_report,
                disable=disabled,
                size=VisualizableSize.S_2,
            )

            behaviors = analyzer_report.report.get("behaviors", [])
            disabled = analyzer_report.status != ReportStatus.SUCCESS or not behaviors or message != "SUCCESS"
            
            crowdsec_behaviors_report = self.VList(
                name=self.Base(
                    value="Crowdsec Behaviors",
                    icon=VisualizableIcon.ALARM,
                    color=VisualizableColor.DANGER,
                    disable=disabled,
                    link = analyzer_report.report.get("link", ""),
                ),
                value=[
                    self.Base(b.get("label", ""), disable=disabled) for b in behaviors
                ],
                start_open=True,
                max_elements_number=5,
                report=analyzer_report,
                disable=disabled,
                size=VisualizableSize.S_2,
            )
            return crowdsec_classification_report, crowdsec_behaviors_report
    
    @visualizable_error_handler_with_params("OTX Alienvault")
    def _otxquery(self):
        try:
            analyzer_report = self.analyzer_reports().get(config__name="OTXQuery")
        except AnalyzerReport.DoesNotExist:
            logger.warning("OTXQuery report does not exist")
        else:
            message = analyzer_report.status
            pulses = analyzer_report.report.get("pulses", [])
            link_otx = pulses[0]["link"]
            disabled = analyzer_report.status != ReportStatus.SUCCESS or not pulses or message != "SUCCESS"
            otx_report = self.VList(
                name=self.Base(
                    value="OTX Alienvault",
                    icon=VisualizableIcon.OTX,
                    color=VisualizableColor.DANGER,
                    disable=disabled,
                    link = link_otx
                ),
                value=[
                    self.Base(
                        value=p.get("name", ""),
                        link=link_otx,
                        disable=disabled,
                    )
                    for p in pulses
                ],
                start_open=True,
                max_elements_number=5,
                report=analyzer_report,
                disable=disabled,
                size=VisualizableSize.S_4,
            )
            return otx_report
    
    @visualizable_error_handler_with_params("BGP Ranking")
    def _bgp_ranking(self):
        try:
            analyzer_report = self.analyzer_reports().get(
                config__name="BGP_Ranking"
            )
        except AnalyzerReport.DoesNotExist:
            logger.warning("BGP_Ranking report does not exist")
        else:
            message = analyzer_report.status
            asn = analyzer_report.report.get("asn", "")
            asn_rank = analyzer_report.report.get("asn_rank", "")
            asn_position = analyzer_report.report.get("asn_position", "")
            asn_description = analyzer_report.report.get("asn_description", "")
            disabled = analyzer_report.status != ReportStatus.SUCCESS or (
                not asn and not asn_rank and not asn_position and not asn_description
            ) or message != "SUCCESS"
            
            ip = self.get_ip()
            link_bgp = f"https://bgpranking.circl.lu/ipasn_history/?ip={ip}/24"
            # curl https://bgpranking-ng.circl.lu/ipasn_history/?ip=143.255.153.0/24
            nl = '\n'
            bgp_ranking_report = self.VList(
                name=self.Base(
                    value="BGP_Ranking",
                    # icon=VisualizableIcon.ALARM,
                    # color=VisualizableColor.DANGER,
                    disable=disabled,
                    link = link_bgp,
                ),
                
                value=[
                    self.Base(value="" if disabled else f"ASN: {asn}{nl} Rank: {asn_rank}{nl} Position: {asn_position}{nl} Description: {asn_description} ")
                ],
                start_open=True,
                max_elements_number=4,
                report=analyzer_report,
                disable=disabled,
                size=VisualizableSize.S_2,
            )
            return bgp_ranking_report

    @visualizable_error_handler_with_params("BinaryEdge")
    def _binaryedge(self):
        try:
            analyzer_report = self.analyzer_reports().get(
                config__name="BinaryEdge"
            )
        except AnalyzerReport.DoesNotExist:
            logger.warning("BinaryEdge report does not exist")
        else:
            message = analyzer_report.status
            hits = (
                analyzer_report.report.get("ip_query_report", {})
                .get("total", 0)
            )
    
            ip_binary = self.get_ip()
            link_binary = f"https://api.binaryedge.io/v2/query/ip/{ip_binary} -H 'X-Key:287accb0-c899-43b3-810a-16ab85b5b987'"
            # curl 'https://api.binaryedge.io/v2/<endpoint>' -H 'X-Key:API_KEY'

            disabled = analyzer_report.status != ReportStatus.SUCCESS or message != "SUCCESS"

            output = "Not Found"
            if hits >= 1:
                output = f"Engine Hits: {hits}"
                result = "Malicious"

            #color
            # if result == "Malicious":
            #     icon = VisualizableIcon.MALWARE
            #     color = VisualizableColor.DANGER
            # else:  # should be "unknown"
            #     icon = VisualizableIcon.SUCCESS
            #     color = VisualizableColor.INFO
            
            binaryedge_report = self.Title(
                self.Base(
                    value="BinaryEdge",
                    link = link_binary,
                    #link=analyzer_report.report["link", ""],
                    #icon=VisualizableIcon.INFO
                ),
                self.Base(value= output),
                disable=analyzer_report.status != ReportStatus.SUCCESS or message != "SUCCESS",
            )
            return binaryedge_report

    @visualizable_error_handler_with_params("Feodo Tracker")
    def _feodotracker(self):
        try:
            analyzer_report = self.analyzer_reports().get(
                config__name="Feodo_Tracker"
            )
        except AnalyzerReport.DoesNotExist:
            logger.warning("FeodoTracker report does not exist")
        else:
            message = analyzer_report.status
            hits = (
                analyzer_report.report.get("found", 0)
            )
            ip_feodo = self.get_ip()
            link_feodo = f"https://feodotracker.abuse.ch/browse.php?search={ip_feodo}"
            FeodoTracker_report = self.Title(
                self.Base(
                    value="Feodo_Tracker",
                    link = link_feodo,
                    # link=analyzer_report.report["link"],
                    # icon=VisualizableIcon.INFO,
                ),
                self.Base(value=f"Malicious: {hits}"),
                disable=analyzer_report.status != ReportStatus.SUCCESS or message != "SUCCESS",
            )
            return FeodoTracker_report
    
    @visualizable_error_handler_with_params("FileScan_Search")
    def _filescan_search(self):
        try:
            analyzer_report = self.analyzer_reports().get(
                config__name="FileScan_Search"
            )
        except AnalyzerReport.DoesNotExist:
            logger.warning("FileScan_Search report does not exist")
        else:
            message = analyzer_report.status
            hits = (
                analyzer_report.report.get("mdcloud", {})
                .get("detected",0)
            )

            ip_filescan = self.get_ip()  # Retrieve IP using get_ip method
            link_filescan = f"https://www.filescan.io/api/reputation/ip?ioc_value={ip_filescan}"
            # https://www.filescan.io/api/reputation/ip?ioc_value=80.244.11.0

            output= "Not Found"
            if hits >= 1:
                output = "Malicious"
            else:
                output = "Not Found"
            #color
            # if output == "Malicious":
            #     icon = VisualizableIcon.MALWARE
            #     color = VisualizableColor.DANGER
            # else:  # should be "unknown"
            #     icon = VisualizableIcon.SUCCESS
            #     color = VisualizableColor.INFO

            filescan_search_report = self.Title(
                self.Base(
                    value="FileScan_Search",
                    link = link_filescan,
                    # color = color,
                    #icon=VisualizableIcon.INFO
                ),
                self.Base(value=output),
                disable=analyzer_report.status != ReportStatus.SUCCESS or message != "SUCCESS",
            )
            return filescan_search_report 
    
    @visualizable_error_handler_with_params("XForceExchange")
    def _x_force_exchange(self):
        try:
            analyzer_report = self.analyzer_reports().get(
                config__name="XForceExchange"
            )
        except AnalyzerReport.DoesNotExist:
            logger.warning("XForceExchange report does not exist")
        else:
            message = analyzer_report.status
            hits = (
                analyzer_report.report.get("ipr",{})
                .get("score",0)
            )
            output = ""
            if hits >= 1 and hits <= 3:
                output = "Risk: Low/None"
            elif hits >= 4 and hits <=5.5:
                output = "Risk: Medium"
            else:
                output = "Risk: High"
            
            #color
            if hits >= 1 and hits <= 3:
                icon = VisualizableIcon.LIKE
                color = VisualizableColor.SUCCESS
            elif hits >= 4 and hits <=5.5:
                icon = VisualizableIcon.WARNING
                color = VisualizableColor.INFO
            else:
                icon = VisualizableIcon.MALWARE
                color = VisualizableColor.DANGER
            
            disabled = analyzer_report.status != ReportStatus.SUCCESS or message != "SUCCESS"

            link_xforce = analyzer_report.report.get("ipr",{}).get("link","")

            # x_force_exchange_report = self.VList(
            #     name = self.Base(
            #         value = "XForceExchange",
            #         color = color,
            #         disable = disabled,
            #         link = link_xforce,
            #     )
            #     value=[
            #         self.Base(value="" if disabled else output)
            #     ],
            #     start_open=True,
            #     max_elements_number=1,
            #     report=analyzer_report,
            #     disable=disabled,
            #     size=VisualizableSize.S_2,
            # )
    
            x_force_exchange_report = self.Title(
                self.Base(
                    value="XForceExchange",
                    link=analyzer_report.report.get("ipr",{}).get("link",""),
                    color = color,
                    #icon=VisualizableIcon.INFO
                ),
                self.Base(value=f"Risk Status: {output}"),
                disable=analyzer_report.status != ReportStatus.SUCCESS or message != "SUCCESS",
            )
            return x_force_exchange_report
    
    @visualizable_error_handler_with_params("VirusTotal")
    def _vt3(self):
        try:
            analyzer_report = self.analyzer_reports().get(
                config__name="VirusTotal_v3_Get_Observable"
            )
        except AnalyzerReport.DoesNotExist:
            logger.warning("VirusTotal_v3_Get_Observable report does not exist")
        else:
            hits = (
                analyzer_report.report.get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
                .get("malicious", 0)
            )

            output = ""
            if hits >= 1:
                output = f"Reported: {hits}"
            else:
                output = "Safe"
            
            #color
            if hits >= 1:
                icon = VisualizableIcon.MALWARE
                color = VisualizableColor.DANGER
                
            else:
                icon = VisualizableIcon.LIKE
                color = VisualizableColor.SUCCESS

            virustotal_report = self.Title(
                self.Base(
                    value="VirusTotal",
                    link=analyzer_report.report["link"],
                    icon=VisualizableIcon.VIRUSTotal,
                    color = color,
                ),
                self.Base(value= output),
                disable=analyzer_report.status != ReportStatus.SUCCESS or not hits,
            )
            return virustotal_report
    
    @visualizable_error_handler_with_params("Tor Project")
    def _tor(self):
        try:
            analyzer_report = self.analyzer_reports().get(config__name="TorProject")
        except AnalyzerReport.DoesNotExist:
            logger.warning("TorProject report does not exist")
        else:
            message = analyzer_report.status
            found = analyzer_report.report.get("found", 0)
            link_tor = f"https://check.torproject.org/torbulkexitlist"

            output = "Not Found"
            if str(found)=="True":
                output = "Malicious"
            else:
                output = "Not Found"

            tor_report = self.Title(self.Base(
                value="Tor Project",   
                link = link_tor             
            ),
            self.Base(value=output),
            disable = analyzer_report.status != ReportStatus.SUCCESS or message != "SUCCESS",
            )
            return tor_report
    
    @visualizable_error_handler_with_params("Tor_Nodes_DanMeUk")
    def _tor_nodes_danmeuk(self):
        try:
            analyzer_report = self.analyzer_reports().get(
                config__name="Tor_Nodes_DanMeUk"
            )
        except AnalyzerReport.DoesNotExist:
            logger.warning("Tor_Nodes_DanMeUk report does not exist")
        else:
            message = analyzer_report.status
            hits = (
                analyzer_report.report.get("found",0)
            )
            ip_tor_dan = self.get_ip()
            link_tor = f"https://www.dan.me.uk/ipinfo?ip={ip_tor_dan}"
            # https://www.dan.me.uk/ipinfo?ip=128.230.49.34

            # output = "Not Found"
            # if str(found)=="True":
            #     output = "Malicious"
            # else:
            #     output = "Not Found"

            tor_nodes_danmeuk_report = self.Title(
                self.Base(
                    value="Tor_Nodes_DanMeUk",
                    link = link_tor,
                    # link=analyzer_report.report["link", ""]
                    #icon=VisualizableIcon.INFO
                ),
                self.Base(value=f"Tor Exit Address Found: {hits}"),
                disable=analyzer_report.status != ReportStatus.SUCCESS or message != "SUCCESS",
            )
            
            return tor_nodes_danmeuk_report
    
    @visualizable_error_handler_with_params("ThreatFox")
    def _threatfox(self):
        try:
            analyzer_report = self.analyzer_reports().get(config__name="ThreatFox")
        except AnalyzerReport.DoesNotExist:
            logger.warning("Threatfox report does not exist")
        else:
            message = analyzer_report.status
            disabled = (
                analyzer_report.status != ReportStatus.SUCCESS
                or analyzer_report.report.get("query_status", "") != "ok"
                or message != "SUCCESS"
            )
            data = analyzer_report.report.get("data", [])
            link = ""
            confidence_level = "Not Found"
            if data and isinstance(data, list):
                confidence_level = data[0].get("confidence_level", 0)
                ioc_id = data[0].get("id", "")
                link=(f"https://threatfox.abuse.ch/ioc/{ioc_id}")
            threatfox_report = self.Title(
                self.Base(
                    value="ThreatFox", link=link
                ),
                self.Base(value="" if disabled else f"Confidence level of malware is: {confidence_level}/100"),
                disable = disabled,

            )
            return threatfox_report
    
    @visualizable_error_handler_with_params("Talos Reputation")
    def _talos(self):
        try:
            analyzer_report = self.analyzer_reports().get(
                config__name="TalosReputation"
            )
        except AnalyzerReport.DoesNotExist:
            logger.warning("TalosReputation report does not exist")
        else:
            message = analyzer_report.status
            found = analyzer_report.report.get("found", 0)
            ip_talos = self.get_ip()
            link_talos = f"https://talosintelligence.com/reputation_center/lookup?search={ip_talos}"

            talos_report = self.Title(self.Base(
                value="Talos Reputation",
                link = link_talos,
            ),
            self.Base(value=f"Engine Hits: {found}"),
            disable = analyzer_report.status != ReportStatus.SUCCESS or message != "SUCCESS",
            )
            return talos_report
    
    @visualizable_error_handler_with_params("Pulsedive")
    def _pulsedive(self):
        try:
            analyzer_report = self.analyzer_reports().get(
                config__name="Pulsedive"
            )
        except AnalyzerReport.DoesNotExist:
            logger.warning("Pulsedive report does not exist")
        else:
            message = analyzer_report.status
            hits = (
                analyzer_report.report.get("risk", 0)
            )
            pulsedive_report = self.Title(
                self.Base(
                    value="Pulsedive",
                    #link=analyzer_report.report["link", ""],
                    #icon=VisualizableIcon.INFO
                ),
                self.Base(value=f"Risk: {hits}"),
                disable=analyzer_report.status != ReportStatus.SUCCESS or message != "SUCCESS",
            )
            return pulsedive_report
    
    @visualizable_error_handler_with_params("Netlas")
    def _netlas(self):
        try:
            analyzer_report = self.analyzer_reports().get(
                config__name="Netlas"
            )
        except AnalyzerReport.DoesNotExist:
            logger.warning("Netlas report does not exist")
        else:
            message = analyzer_report.status
            # ip = analyzer_report.report.get("ip", {})
            asn = analyzer_report.report.get("asn", {})
            
            
            if isinstance(asn, dict):
                asn_name = asn.get("name", "")
                asn_country = asn.get("country", "")
                asn_registry = asn.get("registry", "")
                ip_netlas = self.get_ip()
                link_netlas = f"https://app.netlas.io/host/{ip_netlas}/"
            else:
                asn_name = "Not Found"
                asn_country = "Not Found"
                asn_registry = "Not Found"

            netlas_report = self.Title(
                self.Base(
                    value="Netlas",
                    link=link_netlas,
                ),
                self.Base(
                    value=f"Details: {asn_name} | Country: {asn_country} | Registry: {asn_registry}"
                ),
                disable=(
                    analyzer_report.status != ReportStatus.SUCCESS
                    or message != "SUCCESS"
                ),
            )
            return netlas_report

    @visualizable_error_handler_with_params("IPQS_Fraud_And_Risk_Scoring")
    def _ipqs(self):
        try:
            analyzer_report = self.analyzer_reports().get(
                config__name="IPQS_Fraud_And_Risk_Scoring"
            )
        except AnalyzerReport.DoesNotExist:
            logger.warning("IPQS_Fraud_And_Risk_Scoring report does not exist")
        else:
            message = analyzer_report.status
            hits = (
                analyzer_report.report.get("fraud_score", 0)
            )

            ip_ipqs = self.get_ip()
            link_ipqs = f"https://www.ipqualityscore.com/ip-lookup/search/{ip_ipqs}"

            ipqs_report = self.Title(
                self.Base(
                    value="IPQS_Fraud_And_Risk_Scoring",
                    link = link_ipqs,
                    # link=analyzer_report.report["link"],
                    # icon=VisualizableIcon.VIRUSTotal,
                ),
                self.Base(value=f"Fraud Score: {hits}"),
                disable=analyzer_report.status != ReportStatus.SUCCESS or message != "SUCCESS",
            )
            return ipqs_report
    
    @visualizable_error_handler_with_params("InQuest_REPdb")
    def _inquest_repdb(self):
        try:
            analyzer_report = self.analyzer_reports().get(config__name="InQuest_REPdb")
        except AnalyzerReport.DoesNotExist:
            logger.warning("InQuest_REPdb report does not exist")
        else:
            success = analyzer_report.report.get("success", False)
            data = analyzer_report.report.get("data", [])
            disabled = (
                analyzer_report.status != ReportStatus.SUCCESS
                or not success
                or not data
            )

            ip_rep = self.get_ip()
            link_rep = f"https://labs.inquest.net/repdb/search/{ip_rep}##eyJyZXN1bHRzIjpbIn4iLCJjdGltZSIsMSwiIixbXV19"
            inquest_rep_report = self.Title(
                self.Base(
                    value="InQuest_REPdb",
                    link=analyzer_report.report.get("link", ""),
                    icon=VisualizableIcon.WARNING,
                ),
                self.Base(value="" if disabled else "found"),
                disable=disabled,
            )
            return inquest_rep_report
    
    @visualizable_error_handler_with_params("InQuest_IOCdb")
    def _inquest_iocdb(self):
        try:
            analyzer_report = self.analyzer_reports().get(
                config__name="InQuest_IOCdb"
            )
        except AnalyzerReport.DoesNotExist:
            logger.warning("InQuest_IOCdb report does not exist")
        else:
            message = analyzer_report.status
            found = analyzer_report.report.get("success", 0)
            ip_ioc = self.get_ip()
            link_ioc = f"https://labs.inquest.net/iocdb/search/{ip_ioc}##eyJyZXN1bHRzIjpbIn4iLCJjdGltZSIsMSwiIixbXV19"
            inquest_iocdb_report = self.Title(
                self.Base(
                    value="InQuest_IOCdb",
                    link = link_ioc,
                    # link=analyzer_report.report.get("link", ""),
                    icon=VisualizableIcon.INFO
                ),
                self.Base(value=f"Not Malicious: {found}"),
                disable = analyzer_report.status != ReportStatus.SUCCESS or message != "SUCCESS",
            )
            return inquest_iocdb_report 

    @visualizable_error_handler_with_params("InQuest_DFI")
    def _InQuestDFI(self):
        try:
            analyzer_report = self.analyzer_reports().get(
                config__name="InQuest_DFI"
            )
        except AnalyzerReport.DoesNotExist:
            logger.warning("InQuest_DFI report does not exist")
        else:
            message = analyzer_report.status
            found = analyzer_report.report.get("success", 0)
            ip_dfi = self.get_ip()
            link_dfi = f"https://labs.inquest.net/dfi/search/ext/ext_code/{ip_dfi}##eyJyZXN1bHRzIjpbIn4iLCJmaXJzdFNlZW4iLDEsIiIsW11dfQ=="
            InQuestDFI_report = self.Title(
                self.Base(
                    value="InQuest_DFI",
                    icon=VisualizableIcon.INFO,
                    link = link_dfi,
                ),
                self.Base(value=f"Not Malicious: {found}"),
                disable = analyzer_report.status != ReportStatus.SUCCESS or message != "SUCCESS",
            )
            return InQuestDFI_report

    @visualizable_error_handler_with_params("GreynoiseCommunity")
    def _greynoisecom(self):
        try:
            analyzer_report = self.analyzer_reports().get(
                config__name="GreyNoiseCommunity"
            )
        except AnalyzerReport.DoesNotExist:
            logger.warning("GreynoiseCommunity report does not exist")
        else:
            message = analyzer_report.report.get("message", None)
            disabled = (
                analyzer_report.status != ReportStatus.SUCCESS or message != "Success"
            )
            # noise = analyzer_report.report.get("noise", "")
            # riot = analyzer_report.report.get("riot", "")
            classification = analyzer_report.report.get("classification", "")
            if classification == "benign":
                icon = VisualizableIcon.LIKE
                color = VisualizableColor.SUCCESS
            elif classification == "malicious":
                icon = VisualizableIcon.MALWARE
                color = VisualizableColor.DANGER
            else:  # should be "unknown"
                icon = VisualizableIcon.WARNING
                color = VisualizableColor.INFO
            
            greynoisecom_report = self.Title(
                self.Base(
                    value="Greynoise Community",
                    link=analyzer_report.report.get("link", ""),
                    # icon=icon,
                ),
                self.Base(value=analyzer_report.report.get("classification", ""), color=color),
                disable=disabled,   
            )
            return greynoisecom_report
    
    @visualizable_error_handler_with_params("GoogleSafebrowsing")
    def _googlesafebrowsing(self):
        try:
            analyzer_report = self.analyzer_reports().get(
                config__name="GoogleSafebrowsing"
            )
        except AnalyzerReport.DoesNotExist:
            logger.warning("GoogleSafebrowsing report does not exist")
        else:
            message = analyzer_report.status 
            found = analyzer_report.report.get("Found", False)
            GoogleSafebrowsing_report = self.Title(
                self.Base(
                    value="GoogleSafebrowsing",
                    icon=VisualizableIcon.INFO
                ),
                self.Base(value=f"Malicious: {found}"),
                disable = analyzer_report.status != ReportStatus.SUCCESS or message != "SUCCESS",
            )
            return GoogleSafebrowsing_report
    
    @visualizable_error_handler_with_params("FireHol_IPList")
    def _firehol(self):
        try:
            analyzer_report = self.analyzer_reports().get(config__name="FireHol_IPList")
        except AnalyzerReport.DoesNotExist:
            logger.warning("FireHol_IPList report does not exist")
        else:
            message = analyzer_report.status
            hits = (
                analyzer_report.report.get("firehol_level1.netset", 0)
            )
            firehol_report = self.Title(
                self.Base(
                    value="FireHol",
                    # link=analyzer_report.report["link", ""]
                    #icon=VisualizableIcon.INFO
                ),
                self.Base(value=f"Tor Exit Address Found: {hits}"),
                disable=analyzer_report.status != ReportStatus.SUCCESS or message != "SUCCESS",
            )
            return firehol_report

    @visualizable_error_handler_with_params("HybridAnalysis_Get_Observable")
    def _hybrid_analysis(self):
        try:
            analyzer_report = self.analyzer_reports().get(
                config__name="HybridAnalysis_Get_Observable"
            )
        except AnalyzerReport.DoesNotExist:
            logger.warning("HybridAnalysis_Get_Observable report does not exist")
        else:
            message = analyzer_report.status
            hits = (
                analyzer_report.report.get("count",0)
            )
            ip_hybrid = self.get_ip()
            link_hybrid = f"https://www.hybrid-analysis.com/search?query={ip_hybrid}"

            # output = "Not Found"
            # if hits >= 1:
            #     output = "Malicious"

            # #color
            # if output == "Malicious":
            #     icon = VisualizableIcon.MALWARE
            #     color = VisualizableColor.DANGER
            # else:  # should be "unknown"
            #     icon = VisualizableIcon.SUCCESS
            #     color = VisualizableColor.INFO
            
            # disabled = analyzer_report.status != ReportStatus.SUCCESS or message != "SUCCESS"

            # hybrid_analyses_report = self.VList(
            #     name=self.Base(
            #         value="HybridAnalysis",
            #         link = link_hybrid,
            #         color = color,
            #         disable = disabled
            #     ),
            #     value=[
            #         self.Base(value="" if disabled else output)
            #     ],
            #     start_open=True,
            #     max_elements_number=2,
            #     report=analyzer_report,
            #     disable=disabled,
            #     size=VisualizableSize.S_2,
            # )
            # return hybrid_analyses_report

            hybrid_analyses_report = self.Title(
                self.Base(
                    value="HybridAnalysis",
                    link = link_hybrid,
                    # link=analyzer_report.report["link", ""]
                    #icon=VisualizableIcon.INFO
                ),
                self.Base(value=f"Tor Exit Address Found: {hits}"),
                disable=analyzer_report.status != ReportStatus.SUCCESS or message != "SUCCESS",
            )
            return hybrid_analyses_report
    
    @visualizable_error_handler_with_params("ONYPHE")
    def _onyphe(self):
        try:
            analyzer_report = self.analyzer_reports().get(
                config__name="ONYPHE"
            )
        except AnalyzerReport.DoesNotExist:
            logger.warning("ONYPHE report does not exist")
        else:
            message = analyzer_report.status
            hits = (
                analyzer_report.report.get("status",0)
            )

            ip_onyphe = self.get_ip()
            link_onyphe = f"https://www.onyphe.io/search?q={ip_onyphe}"

            onyphe_report = self.Title(
                self.Base(
                    value="ONYPHE",
                    link = link_onyphe,
                    # link=analyzer_report.report["link", ""]
                    #icon=VisualizableIcon.INFO
                ),
                self.Base(value=f"Risk Score: {hits}"),
                disable=analyzer_report.status != ReportStatus.SUCCESS or message != "SUCCESS",
            )
            return onyphe_report
    
    @visualizable_error_handler_with_params("TweetFeed")
    def _tweetfeed(self):
        try:
            analyzer_report = self.analyzer_reports().get(
                config__name="TweetFeed"
            )
        except AnalyzerReport.DoesNotExist:
            logger.warning("TweetFeed report does not exist")
        else:
            message = analyzer_report.status
            hits = (
                analyzer_report.report.get("found",0)
            )
            ip_tweet = self.get_ip()
            link_tweet = f"https://api.tweetfeed.live/v1/month/{ip_tweet}"
            # https://api.tweetfeed.live/v1/{time}/{filter1}/{filter2}
            tweetfeed_report = self.Title(
                self.Base(
                    value="TweetFeed",
                    link = link_tweet,
                    # link=analyzer_report.report["link", ""]
                    #icon=VisualizableIcon.INFO
                ),
                self.Base(value=f"Tor Exit Address: {hits}"),
                disable=analyzer_report.status != ReportStatus.SUCCESS or message != "SUCCESS",
            )
            return tweetfeed_report

    def run(self) -> List[Dict]:
        first_level_elements = []
        second_level_elements = []
        third_level_elements = []
        fourth_level_elements = []
        fifth_level_elements = []
        sixth_level_elements = []
        seventh_level_elements = []

        #first level elements
        first_level_elements.append(self._bgp_ranking())

        first_level_elements.append(self._netlas())

        abuse_report, abuse_categories_report = self._abuse_ipdb()
        first_level_elements.append(abuse_report)

        first_level_elements.append(abuse_categories_report)

        #second level elements
        second_level_elements.append(self._feodotracker())

        second_level_elements.append(self._filescan_search())

        second_level_elements.append(self._x_force_exchange())

        second_level_elements.append(self._vt3())

        second_level_elements.append(self._binaryedge())

        #Third Level Elements
        third_level_elements.append(self._tor_nodes_danmeuk())

        third_level_elements.append(self._tor())

        third_level_elements.append(self._threatfox())

        third_level_elements.append(self._talos())

        third_level_elements.append(self._pulsedive())

        #Fouth Level Elements
        fourth_level_elements.append(self._otxquery())

        fourth_level_elements.append(self._ipqs())

        fourth_level_elements.append(self._inquest_repdb())

        fourth_level_elements.append(self._inquest_iocdb())

        fourth_level_elements.append(self._InQuestDFI())

        #Fifth Level Elements
        fifth_level_elements.append(self._greynoisecom())

        fifth_level_elements.append(self._googlesafebrowsing())

        fifth_level_elements.append(self._firehol())

        fifth_level_elements.append(self._hybrid_analysis())

        fifth_level_elements.append(self._onyphe())

        #Sixth Level Elements
        crowdsec_classification_report, crowdsec_behaviors_report = self._crowdsec()
        sixth_level_elements.append(crowdsec_classification_report)

        sixth_level_elements.append(crowdsec_behaviors_report)

        sixth_level_elements.append(self._tweetfeed())



        page = self.Page(name="Reputation")
        page.add_level(
            self.Level(
                position=1,
                size=self.LevelSize.S_3,
                horizontal_list=self.HList(value=first_level_elements),
            )
        )
        page.add_level(
            self.Level(
                position=2,
                size=self.LevelSize.S_5,
                horizontal_list=self.HList(value=second_level_elements),
            )
        )
        page.add_level(
            self.Level(
                position=3,
                size=self.LevelSize.S_6,
                horizontal_list=self.HList(value=third_level_elements),
            )
        )
        page.add_level(
            self.Level(
                position=4,
                size=self.LevelSize.S_6,
                horizontal_list=self.HList(value=fourth_level_elements),
            )
        )
        page.add_level(
            self.Level(
                position=5,
                size=self.LevelSize.S_6,
                horizontal_list=self.HList(value=fifth_level_elements),
            )
        )
        page.add_level(
            self.Level(
                position=6,
                size=self.LevelSize.S_6,
                horizontal_list=self.HList(value=sixth_level_elements),
            )
        )
        logger.debug(f"levels: {page.to_dict()}")
        return [page.to_dict()]

    @classmethod
    def _monkeypatch(cls):
        patches = []
        return super()._monkeypatch(patches=patches)
