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

from api_app.visualizers_manager.visualizers.apiKeys import (
    binary_edge_api
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

    @visualizable_error_handler_with_params("VirusTotal")
    def _vt3(self):
        try:
            analyzer_report = self.analyzer_reports().get(
                config__name="VirusTotal_v3_Get_Observable"
            )
        except AnalyzerReport.DoesNotExist:
            logger.warning("VirusTotal_v3_Get_Observable report does not exist")
        else:
            message = analyzer_report.status

            hits = (
                analyzer_report.report.get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
                .get("malicious", 0)
            )

            virustotal_report = self.Title(
                self.Base(
                    value="VirusTotal",
                    link=analyzer_report.report["link"],
                    icon=VisualizableIcon.VIRUSTotal,
                ),
                self.Base(value=f"Engine Hits: {hits}"),
                disable=analyzer_report.status != ReportStatus.SUCCESS or message != "SUCCESS",
            )
            return virustotal_report

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
            link_rep = f"https://labs.inquest.net/api/repdb/search?keyword={ip_rep}&filter_by="
            # "https://labs.inquest.net/api/repdb/search?keyword=85.114.96.11&filter_by="
            inquest_report = self.Title(
                self.Base(
                    value="InQuest",
                    link=analyzer_report.report.get("link", ""),
                    icon=VisualizableIcon.WARNING,
                ),
                self.Base(value="" if disabled else "found"),
                disable=disabled,
            )
            return inquest_report

    @visualizable_error_handler_with_params("AbuseIPDB Categories")
    def _abuse_ipdb(self):
        try:
            analyzer_report = self.analyzer_reports().get(config__name="AbuseIPDB")
        except AnalyzerReport.DoesNotExist:
            logger.warning("AbuseIPDB report does not exist")
            return None, None
        else:
            message = analyzer_report.status
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
                or message != "SUCCESS"
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
            disabled = analyzer_report.status != ReportStatus.SUCCESS or not pulses or message != "SUCCESS"
            otx_report = self.VList(
                name=self.Base(
                    value="OTX Alienvault",
                    icon=VisualizableIcon.OTX,
                    color=VisualizableColor.DANGER,
                    disable=disabled,
                ),
                value=[
                    self.Base(
                        value=p.get("name", ""),
                        link=p.get("link", ""),
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
            tor_report = self.Title(self.Base(
                value="Tor Exit Node",   
                link = link_tor             
            ),
            self.Base(value=f"Found as Tor Exit Node: {found}"),
            disable = analyzer_report.status != ReportStatus.SUCCESS or message != "SUCCESS",
            )
            return tor_report

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
            talos_report = self.Title(self.Base(
                value="Talos Reputation",
            ),
            self.Base(value=f"Engine Hits: {found}"),
            disable = analyzer_report.status != ReportStatus.SUCCESS or message != "SUCCESS",
            )
            return talos_report
    
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
            # ip_binary = analyzer_report.report.get("ip_query_report", {}).get("query", "")
            # ip_binary = ip_binary[3:]
            # api_key = binary_edge_api
            ip_binary = self.get_ip()
            link_binary = f"https://api.binaryedge.io/v2/query/ip/{ip_binary} -H 'X-Key:287accb0-c899-43b3-810a-16ab85b5b987'"
            # curl 'https://api.binaryedge.io/v2/<endpoint>' -H 'X-Key:API_KEY'
            binaryedge_report = self.Title(
                self.Base(
                    value="BinaryEdge",
                    link = link_binary,
                    #link=analyzer_report.report["link", ""],
                    #icon=VisualizableIcon.INFO
                ),
                self.Base(value=f"Engine Hits: {hits}"),
                disable=analyzer_report.status != ReportStatus.SUCCESS or message != "SUCCESS",
            )
            return binaryedge_report
        
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
            bgp_ranking_report = self.Title(
                self.Base(
                    value="BGP_Ranking",
                    link = link_bgp,
                    #link=analyzer_report.report["link", ""],
                    # icon=VisualizableIcon.INFO
                ),
                self.Base(value="" if disabled else f"ASN: {asn}| Rank: {asn_rank}| Position: {asn_position}| Description: {asn_description} "),
                disable=disabled,
            )
            return bgp_ranking_report
        
    # @visualizable_error_handler_with_params("ONYPHE")
    # def _onyphe(self):
    #     try:
    #         analyzer_report = self.analyzer_reports().get(
    #             config__name="ONYPHE"
    #         )
    #     except AnalyzerReport.DoesNotExist:
    #         logger.warning("ONYPHE report does not exist")
    #     else:
    #         message = analyzer_report.status
    #         hits = (
    #             analyzer_report.report.get("status",0)
    #         )
    #         onyphe_report = self.Title(
    #             self.Base(
    #                 value="ONYPHE",
    #                 # link=analyzer_report.report["link", ""]
    #                 #icon=VisualizableIcon.INFO
    #             ),
    #             self.Base(value=f"Risk Score: {hits}"),
    #             disable=analyzer_report.status != ReportStatus.SUCCESS or message != "SUCCESS",
    #         )
    #         return onyphe_report
            
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
            x_force_exchange_report = self.Title(
                self.Base(
                    value="XForceExchange",
                    link=analyzer_report.report.get("ipr",{}).get("link",""),
                    #icon=VisualizableIcon.INFO
                ),
                self.Base(value=f"Risk Status: {hits}"),
                disable=analyzer_report.status != ReportStatus.SUCCESS or message != "SUCCESS",
            )
            return x_force_exchange_report

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
            ipqs_report = self.Title(
                self.Base(
                    value="IPQS_Fraud_And_Risk_Scoring",
                    # link=analyzer_report.report["link"],
                    # icon=VisualizableIcon.VIRUSTotal,
                ),
                self.Base(value=f"Fraud Score: {hits}"),
                disable=analyzer_report.status != ReportStatus.SUCCESS or message != "SUCCESS",
            )
            return ipqs_report

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
            tor_nodes_danmeuk_report = self.Title(
                self.Base(
                    value="Tor_Nodes_DanMeUk",
                    link = link_tor,
                    # link=analyzer_report.report["link", ""]
                    #icon=VisualizableIcon.INFO
                ),
                self.Base(value=f"Tor Exit Address: {hits}"),
                disable=analyzer_report.status != ReportStatus.SUCCESS or message != "SUCCESS",
            )
            return tor_nodes_danmeuk_report

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
            tweetfeed_report = self.Title(
                self.Base(
                    value="TweetFeed",
                    
                    # link=analyzer_report.report["link", ""]
                    #icon=VisualizableIcon.INFO
                ),
                self.Base(value=f"Tor Exit Address: {hits}"),
                disable=analyzer_report.status != ReportStatus.SUCCESS or message != "SUCCESS",
            )
            return tweetfeed_report
    
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
            link_dfi = f"https://labs.inquest.net/api/dfi/search/ext/ext_code?ml_only=false&av_only=false&keyword={ip_dfi}"
            # "https://labs.inquest.net/api/dfi/search/ext/ext_code?ml_only=false&av_only=false&keyword=182.134.239.97"
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
            sha_hybrid = analyzer_report.report.get("result",{})
            sha_hybrid = sha_hybrid[0]["sha256"]
            # link_hybrid = f"https://www.hybrid-analysis.com/api/v2/overview/{sha_hybrid} \ -H 'api-key: uxwbea3zfde01fadnv0e9h3990e273cepk4iw2qob6b31882g3jo8zmy005d2277'"
            # https://www.hybrid-analysis.com/api/v2/overview/e93f8d463bb6b2afdb86e2adf6e23fb93dc59be59b2873ecf5c6c4c578df9441

            hybrid_analyses_report = self.Title(
                self.Base(
                    value="HybridAnalysis_Get_Observable",
                    link = link_hybrid,
                    # link=analyzer_report.report["link", ""]
                    #icon=VisualizableIcon.INFO
                ),
                self.Base(value=f"Tor Exit Address Found: {hits}"),
                disable=analyzer_report.status != ReportStatus.SUCCESS or message != "SUCCESS",
            )
            return hybrid_analyses_report

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
            link_ioc = f"https://labs.inquest.net/api/iocdb/search?keyword={ip_ioc}&filter_by="
            # "https://labs.inquest.net/api/iocdb/search?keyword=43.138.168.21&filter_by="
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
            # ip_filescan = analyzer_report.report.get("ioc_value", "")
            ip = self.get_ip()  # Retrieve IP using get_ip method
            link_filescan =  (f"https://www.filescan.io/api/reputation/ip?ioc_value={ip}" )
            filescan_search_report = self.Title(
                self.Base(
                    value="FileScan_Search",
                    #link=analyzer_report.report["link", ""],
                    link = link_filescan,
                    #icon=VisualizableIcon.INFO
                ),
                self.Base(value=f"Malicious: {hits}/1"),
                disable=analyzer_report.status != ReportStatus.SUCCESS or message != "SUCCESS",
            )
            return filescan_search_report    

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
                link_netlas = f"https://app.netlas.io/api/whois_ip/?q={ip_netlas}&source_type=include&start=0&fields=*"
            else:
                asn_name = "Not Found"
                asn_country = "Not Found"
                asn_registry = "Not Found"
 
            # if ip and isinstance(ip, dict):
            #     ipadd = analyzer_report.report.get("ip", {}).get("gte", "")
            #     link = f"https://app.netlas.io/api/whois_ip/?q={ipadd}&source_type=include&start=0&fields=*"
            # else:
            #     ipadd = ""
            #     link = ""


 
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

    def run(self) -> List[Dict]:
        first_level_elements = []
        second_level_elements = []
        third_level_elements = []
        fourth_level_elements = []
        fifth_level_elements = []
        sixth_level_elements = []
        seventh_level_elements = []

        # First Level Elements
        abuse_report, abuse_categories_report = self._abuse_ipdb()
        first_level_elements.append(abuse_report)

        crowdsec_classification_report, crowdsec_behaviors_report = self._crowdsec()
        first_level_elements.append(crowdsec_classification_report)

        #Second Level Elements
        second_level_elements.append(self._firehol())

        second_level_elements.append(self._tor())

        second_level_elements.append(self._talos())

        second_level_elements.append(self._tweetfeed())

        second_level_elements.append(self._tor_nodes_danmeuk())

        #Third Level Elements
        third_level_elements.append(self._googlesafebrowsing())

        third_level_elements.append(self._inquest_repdb())

        third_level_elements.append(self._InQuestDFI())

        third_level_elements.append(self._inquest_iocdb())

        third_level_elements.append(self._feodotracker())

        #Fourth Level Elements
        fourth_level_elements.append(self._pulsedive())

        fourth_level_elements.append(self._vt3())

        fourth_level_elements.append(self._binaryedge())

        fourth_level_elements.append(self._x_force_exchange())

        fourth_level_elements.append(self._hybrid_analysis())

        #Fifth Level Elements
        # fifth_level_elements.append(self._onyphe())

        fifth_level_elements.append(self._ipqs())

        fifth_level_elements.append(self._filescan_search())

        fifth_level_elements.append(self._greynoisecom())

        fifth_level_elements.append(self._threatfox())

        fifth_level_elements.append(self._netlas())

        #Sixth Level Elements
        sixth_level_elements.append(self._bgp_ranking())

        #Seventh Level Elements
        seventh_level_elements.append(abuse_categories_report)

        seventh_level_elements.append(crowdsec_behaviors_report)

        seventh_level_elements.append(self._otxquery())

        
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
            size=self.LevelSize.S_4,
            horizontal_list=self.HList(value=fourth_level_elements),
            )
        )
        page.add_level(
            self.Level(
                position=5,
                size=self.LevelSize.S_4,
                horizontal_list=self.HList(value=fifth_level_elements),
            )
        )
        page.add_level(
            self.Level(
                position=6,
                size=self.LevelSize.S_4,
                horizontal_list=self.HList(value=sixth_level_elements),
            )
        )
        page.add_level(
            self.Level(
                position=7,
                size=self.LevelSize.S_4,
                horizontal_list=self.HList(value=seventh_level_elements),
            )
        )
        logger.debug(f"levels: {page.to_dict()}")
        return [page.to_dict()]

    @classmethod
    def _monkeypatch(cls):
        patches = []
        return super()._monkeypatch(patches=patches)
