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
            virustotal_report = self.Title(
                self.Base(
                    value="VirusTotal",
                    link=analyzer_report.report["link"],
                    icon=VisualizableIcon.VIRUSTotal,
                ),
                self.Base(value=f"Engine Hits: {hits}"),
                disable=analyzer_report.status != ReportStatus.SUCCESS or not hits,
            )
            return virustotal_report

    @visualizable_error_handler_with_params("Greynoise")
    def _greynoise(self):
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
            greynoise_report = self.Title(
                self.Base(
                    value="Greynoise",
                    link=analyzer_report.report.get("link", ""),
                    icon=icon,
                ),
                self.Base(value=analyzer_report.report.get("name", ""), color=color),
                disable=disabled,
            )
            return greynoise_report

    @visualizable_error_handler_with_params("URLhaus")
    def _urlhaus(self):
        try:
            analyzer_report = self.analyzer_reports().get(config__name="URLhaus")
        except AnalyzerReport.DoesNotExist:
            logger.warning("URLhaus report does not exist")
        else:
            disabled = (
                analyzer_report.status != ReportStatus.SUCCESS
                or analyzer_report.report.get("query_status", None) != "ok"
            )
            urlhaus_report = self.Title(
                self.Base(
                    value="URLhaus",
                    link=analyzer_report.report.get("urlhaus_reference", ""),
                    icon=VisualizableIcon.URLHAUS,
                ),
                self.Base(
                    value=""
                    if disabled
                    else f'found {analyzer_report.report.get("urlhaus_status", "")}'
                ),
                disable=disabled,
            )
            return urlhaus_report

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

    @visualizable_error_handler_with_params("InQuest")
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

    @visualizable_error_handler_with_params("GreedyBear Honeypots")
    def _greedybear(self):
        try:
            analyzer_report = self.analyzer_reports().get(config__name="GreedyBear")
        except AnalyzerReport.DoesNotExist:
            logger.warning("GreedyBear report does not exist")
        else:
            found = analyzer_report.report.get("found", False)
            disabled = analyzer_report.status != ReportStatus.SUCCESS or not found
            ioc = analyzer_report.report.get("ioc", {})
            honeypots = []
            if ioc:
                honeypots = list(ioc.get("general_honeypot", []))
                if ioc.get("cowrie"):
                    honeypots.append("Cowrie")
                if ioc.get("log4j"):
                    honeypots.append("Log4Pot")
            gb_report = self.VList(
                name=self.Base(
                    value="GreedyBear Honeypots",
                    icon=VisualizableIcon.WARNING,
                    color=VisualizableColor.DANGER,
                    disable=disabled,
                ),
                value=[self.Base(h, disable=disabled) for h in honeypots],
                start_open=True,
                max_elements_number=5,
                report=analyzer_report,
                disable=disabled,
                size=VisualizableSize.S_2,
            )
            return gb_report

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
            classifications = analyzer_report.report.get("classifications", {})
            sub_classifications = classifications.get("classifications", [])
            false_positives = classifications.get("false_positives", [])
            all_class = sub_classifications + false_positives
            disabled = analyzer_report.status != ReportStatus.SUCCESS or not all_class
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
            disabled = analyzer_report.status != ReportStatus.SUCCESS or not behaviors
            crowdsec_behaviors_report = self.VList(
                name=self.Base(
                    value="Crowdsec Behaviors",
                    icon=VisualizableIcon.ALARM,
                    color=VisualizableColor.DANGER,
                    disable=disabled,
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
            pulses = analyzer_report.report.get("pulses", [])
            disabled = analyzer_report.status != ReportStatus.SUCCESS or not pulses
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

    @visualizable_error_handler_with_params("FireHol")
    def _firehol(self):
        try:
            analyzer_report = self.analyzer_reports().get(config__name="FireHol_IPList")
        except AnalyzerReport.DoesNotExist:
            logger.warning("FireHol_IPList report does not exist")
        else:
            found_in_lists = []
            for report, found in analyzer_report.report.items():
                if found:
                    found_in_lists.append(report)
            disabled = (
                analyzer_report.status != ReportStatus.SUCCESS or not found_in_lists
            )
            otx_report = self.VList(
                name=self.Base(
                    value="FireHol", icon=VisualizableIcon.FIRE, disable=disabled
                ),
                value=[self.Base(f, disable=disabled) for f in found_in_lists],
                start_open=True,
                max_elements_number=5,
                report=analyzer_report,
                disable=disabled,
            )
            return otx_report

    @visualizable_error_handler_with_params("Tor Exit Node")
    def _tor(self):
        try:
            analyzer_report = self.analyzer_reports().get(config__name="TorProject")
        except AnalyzerReport.DoesNotExist:
            logger.warning("TorProject report does not exist")
        else:
            found = analyzer_report.report.get("found", 0)
            tor_report = self.Title(self.Base(
                value="Tor Exit Node",                
            ),
            self.Base(value=f"Found as Tor Exit Node: {found}"),
            disable = analyzer_report.status != ReportStatus.SUCCESS and found,
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
            found = analyzer_report.report.get("found", 0)
            talos_report = self.Title(self.Base(
                value="Talos Reputation",
            ),
            self.Base(value=f"Engine Hits: {found}"),
            disable = analyzer_report.status != ReportStatus.SUCCESS and found,
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
            hits = (
                analyzer_report.report.get("ip_query_report", {})
                .get("total", 0)
            )
            binaryedge_report = self.Title(
                self.Base(
                    value="BinaryEdge",
                    #link=analyzer_report.report["link", ""],
                    #icon=VisualizableIcon.INFO
                ),
                self.Base(value=f"Engine Hits: {hits}"),
                disable=analyzer_report.status != ReportStatus.SUCCESS or not hits,
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
            
    
            asn = analyzer_report.report.get("asn", "")
            asn_rank = analyzer_report.report.get("asn_rank", "")
            asn_position = analyzer_report.report.get("asn_position", "")
            asn_description = analyzer_report.report.get("asn_description", "")
            disabled = analyzer_report.status != ReportStatus.SUCCESS or (
                not asn and not asn_rank and not asn_position and not asn_description
            )
            bgp_ranking_report = self.Title(
                self.Base(
                    value="BGP_Ranking",
                    #link=analyzer_report.report["link", ""],
                    icon=VisualizableIcon.INFO
                ),
                self.Base(value="" if disabled else f"ASN: {asn}| Rank: {asn_rank}| Position: {asn_position}| Description: {asn_description}"),
                disable=disabled,
            )
            return bgp_ranking_report
        
    @visualizable_error_handler_with_params("ONYPHE")
    def _onyphe(self):
        try:
            analyzer_report = self.analyzer_reports().get(
                config__name="ONYPHE"
            )
        except AnalyzerReport.DoesNotExist:
            logger.warning("ONYPHE report does not exist")
        else:
            hits = (
                analyzer_report.report.get("status",0)
            )
            onyphe_report = self.Title(
                self.Base(
                    value="ONYPHE",
                    # link=analyzer_report.report["link", ""]
                    #icon=VisualizableIcon.INFO
                ),
                self.Base(value=f"Risk Score: {hits}"),
                disable=analyzer_report.status != ReportStatus.SUCCESS or not hits,
            )
            return onyphe_report
            
    @visualizable_error_handler_with_params("XForceExchange")
    def _x_force_exchange(self):
        try:
            analyzer_report = self.analyzer_reports().get(
                config__name="XForceExchange"
            )
        except AnalyzerReport.DoesNotExist:
            logger.warning("XForceExchange report does not exist")
        else:
            hits = (
                analyzer_report.report.get("ipr",{})
                .get("score",0)
            )
            x_force_exchange_report = self.Title(
                self.Base(
                    value="XForceExchange",
                    # link=analyzer_report.report["link", ""]
                    #icon=VisualizableIcon.INFO
                ),
                self.Base(value=f"Risk Status: {hits}"),
                disable=analyzer_report.status != ReportStatus.SUCCESS or not hits,
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
                disable=analyzer_report.status != ReportStatus.SUCCESS or not hits,
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
                disable=analyzer_report.status != ReportStatus.SUCCESS or not hits,
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
            hits = (
                analyzer_report.report.get("found",0)
            )
            tor_nodes_danmeuk_report = self.Title(
                self.Base(
                    value="Tor_Nodes_DanMeUk",
                    # link=analyzer_report.report["link", ""]
                    #icon=VisualizableIcon.INFO
                ),
                self.Base(value=f"Tor Exit Address: {hits}"),
                disable=analyzer_report.status != ReportStatus.SUCCESS or not hits,
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
                disable=analyzer_report.status != ReportStatus.SUCCESS or not hits,
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
            found = analyzer_report.report.get("Found", False)
            GoogleSafebrowsing_report = self.Title(
                self.Base(
                    value="GoogleSafebrowsing",
                    icon=VisualizableIcon.INFO
                ),
                self.Base(value=f"Malicious: {found}"),
                disable = analyzer_report.status != ReportStatus.SUCCESS or not found,
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
            found = analyzer_report.report.get("success", 0)
            InQuestDFI_report = self.Title(
                self.Base(
                    value="InQuest_DFI",
                    icon=VisualizableIcon.INFO
                ),
                self.Base(value=f"Not Malicious: {found}"),
                disable = analyzer_report.status != ReportStatus.SUCCESS or not found,
            )
            return InQuestDFI_report
        
    @visualizable_error_handler_with_params("FeodoTracker")
    def _feodotracker(self):
        try:
            analyzer_report = self.analyzer_reports().get(
                config__name="FeodoTracker"
            )
        except AnalyzerReport.DoesNotExist:
            logger.warning("FeodoTracker report does not exist")
        else:
            hits = (
                analyzer_report.report.get("found", 0)
            )
            FeodoTracker_report = self.Title(
                self.Base(
                    value="FeodoTracker",
                    # link=analyzer_report.report["link"],
                    # icon=VisualizableIcon.INFO,
                ),
                self.Base(value=f"Malicious? {hits}"),
                disable=analyzer_report.status != ReportStatus.SUCCESS or not hits,
            )
            return FeodoTracker_report
        
    

    def run(self) -> List[Dict]:
        first_level_elements = []
        second_level_elements = []
        third_level_elements = []
        fourth_level_elements = []
        fifth_level_elements = []
        sixth_level_elements = []
        
        first_level_elements.append(self._vt3())

        first_level_elements.append(self._greynoise())

        first_level_elements.append(self._urlhaus())

        first_level_elements.append(self._threatfox())

        first_level_elements.append(self._inquest_repdb())

        abuse_report, abuse_categories_report = self._abuse_ipdb()
        third_level_elements.append(abuse_report)

        gb_report = self._greedybear()

        crowdsec_classification_report, crowdsec_behaviors_report = self._crowdsec()
        second_level_elements.append(crowdsec_classification_report)

        second_level_elements.append(gb_report)

        second_level_elements.append(abuse_categories_report)

        second_level_elements.append(crowdsec_behaviors_report)

        second_level_elements.append(self._otxquery())

        third_level_elements.append(self._firehol())

        third_level_elements.append(self._tor())

        third_level_elements.append(self._talos())

        fourth_level_elements.append(self._binaryedge())

        #fourth_level_elements.append(self._bgp_ranking())
        
        fourth_level_elements.append(self._pulsedive())
        
        fourth_level_elements.append(self._x_force_exchange())
        
        fourth_level_elements.append(self._onyphe())

        fifth_level_elements.append(self._ipqs())

        fifth_level_elements.append(self._tweetfeed())

        fifth_level_elements.append(self._tor_nodes_danmeuk())

        fifth_level_elements.append(self._googlesafebrowsing())

        fifth_level_elements.append(self._InQuestDFI())

        sixth_level_elements.append(self._feodotracker())
        
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
        logger.debug(f"levels: {page.to_dict()}")
        return [page.to_dict()]

    @classmethod
    def _monkeypatch(cls):
        patches = []
        return super()._monkeypatch(patches=patches)
