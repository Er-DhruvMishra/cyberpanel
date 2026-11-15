from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import datetime, timedelta
import json
import time


class Command(BaseCommand):
    help = 'Run scheduled AI security scans'

    def add_arguments(self, parser):
        parser.add_argument(
            '--daemon',
            action='store_true',
            help='Run as daemon, checking for scheduled scans every minute',
        )
        parser.add_argument(
            '--scan-id',
            type=int,
            help='Run a specific scheduled scan by ID',
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Show detailed information about all scheduled scans',
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force run all active scheduled scans immediately, ignoring schedule',
        )

    def handle(self, *args, **options):
        self.verbose = options.get('verbose', False)
        self.force = options.get('force', False)
        
        if options['daemon']:
            self.stdout.write('Starting scheduled scan daemon...')
            self.run_daemon()
        elif options['scan_id']:
            self.stdout.write(f'Running scheduled scan ID {options["scan_id"]}...')
            self.run_scheduled_scan_by_id(options['scan_id'])
        elif options['force']:
            self.stdout.write('Force running all active scheduled scans...')
            self.force_run_all_scans()
        else:
            self.stdout.write('Checking for scheduled scans to run...')
            self.check_and_run_scans()

    def run_daemon(self):
        """Run as daemon, checking for scans every minute"""
        while True:
            try:
                self.stdout.write(f'\n[{timezone.now().strftime("%Y-%m-%d %H:%M:%S UTC")}] Checking for scheduled scans...')
                self.check_and_run_scans()
                time.sleep(60)  # Check every minute
            except KeyboardInterrupt:
                self.stdout.write('\nDaemon stopped by user')
                break
            except Exception as e:
                self.stderr.write(f'Error in daemon: {str(e)}')
                from plogical.CyberCPLogFileWriter import CyberCPLogFileWriter as logging
                logging.writeToFile(f'[Scheduled Scan Daemon] Error: {str(e)}')
                time.sleep(60)  # Continue after error

    def force_run_all_scans(self):
        """Force run all active scheduled scans immediately"""
        from aiScanner.models import ScheduledScan
        from plogical.CyberCPLogFileWriter import CyberCPLogFileWriter as logging
        
        # Find all active scheduled scans
        active_scans = ScheduledScan.objects.filter(status='active')
        
        if active_scans.count() == 0:
            self.stdout.write('No active scheduled scans found')
            logging.writeToFile('[Scheduled Scan Force] No active scheduled scans found')
            return
        
        self.stdout.write(f'Found {active_scans.count()} active scheduled scans to force run')
        logging.writeToFile(f'[Scheduled Scan Force] Found {active_scans.count()} active scheduled scans to force run')
        
        for scan in active_scans:
            self.stdout.write(f'Force running scheduled scan: {scan.name} (ID: {scan.id})')
            logging.writeToFile(f'[Scheduled Scan Force] Force running scheduled scan: {scan.name} (ID: {scan.id})')
            self.execute_scheduled_scan(scan)

    def check_and_run_scans(self):
        """Check for scheduled scans that need to run"""
        from aiScanner.models import ScheduledScan
        from plogical.CyberCPLogFileWriter import CyberCPLogFileWriter as logging
        
        now = timezone.now()
        
        # Log all scheduled scans and their status
        all_scans = ScheduledScan.objects.all()
        self.stdout.write(f'Total scheduled scans: {all_scans.count()}')
        logging.writeToFile(f'[Scheduled Scan Check] Total scheduled scans: {all_scans.count()}')
        
        for scan in all_scans:
            if self.verbose:
                self.stdout.write(f'\n--- Scan Details: {scan.name} (ID: {scan.id}) ---')
                self.stdout.write(f'  Owner: {scan.admin.userName}')
                self.stdout.write(f'  Frequency: {scan.frequency}')
                self.stdout.write(f'  Scan Type: {scan.scan_type}')
                self.stdout.write(f'  Status: {scan.status}')
                self.stdout.write(f'  Domains: {", ".join(scan.domain_list)}')
                self.stdout.write(f'  Created: {scan.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")}')
                if scan.last_run:
                    self.stdout.write(f'  Last Run: {scan.last_run.strftime("%Y-%m-%d %H:%M:%S UTC")}')
                else:
                    self.stdout.write(f'  Last Run: Never')
            
            if scan.status != 'active':
                reason = f'Scan "{scan.name}" (ID: {scan.id}) is not active (status: {scan.status})'
                self.stdout.write(f'  ❌ {reason}')
                logging.writeToFile(f'[Scheduled Scan Check] {reason}')
                continue
            
            if scan.next_run is None:
                reason = f'Scan "{scan.name}" (ID: {scan.id}) has no next_run scheduled'
                self.stdout.write(f'  ❌ {reason}')
                logging.writeToFile(f'[Scheduled Scan Check] {reason}')
                # Try to calculate next run
                if self.verbose:
                    self.stdout.write(f'  🔧 Attempting to calculate next run time...')
                    try:
                        scan.next_run = scan.calculate_next_run()
                        scan.save()
                        self.stdout.write(f'  ✅ Next run set to: {scan.next_run.strftime("%Y-%m-%d %H:%M:%S UTC")}')
                    except Exception as e:
                        self.stdout.write(f'  ❌ Failed to calculate next run: {str(e)}')
                continue
            
            if scan.next_run > now:
                time_until_run = scan.next_run - now
                days = int(time_until_run.total_seconds() // 86400)
                hours = int((time_until_run.total_seconds() % 86400) // 3600)
                minutes = int((time_until_run.total_seconds() % 3600) // 60)
                
                time_str = ""
                if days > 0:
                    time_str = f"{days}d {hours}h {minutes}m"
                else:
                    time_str = f"{hours}h {minutes}m"
                
                reason = f'Scan "{scan.name}" (ID: {scan.id}) scheduled to run in {time_str} at {scan.next_run.strftime("%Y-%m-%d %H:%M:%S UTC")}'
                self.stdout.write(f'  ⏰ {reason}')
                logging.writeToFile(f'[Scheduled Scan Check] {reason}')
                continue
        
        # Find scans that are due to run
        due_scans = ScheduledScan.objects.filter(
            status='active',
            next_run__lte=now
        )
        
        if due_scans.count() == 0:
            self.stdout.write('No scheduled scans are due to run at this time')
            logging.writeToFile('[Scheduled Scan Check] No scheduled scans are due to run at this time')
        else:
            self.stdout.write(f'Found {due_scans.count()} scans due to run')
            logging.writeToFile(f'[Scheduled Scan Check] Found {due_scans.count()} scans due to run')
        
        for scan in due_scans:
            self.stdout.write(f'Running scheduled scan: {scan.name} (ID: {scan.id})')
            logging.writeToFile(f'[Scheduled Scan Check] Running scheduled scan: {scan.name} (ID: {scan.id})')
            self.execute_scheduled_scan(scan)

    def run_scheduled_scan_by_id(self, scan_id):
        """Run a specific scheduled scan by ID"""
        from aiScanner.models import ScheduledScan
        
        try:
            scan = ScheduledScan.objects.get(id=scan_id)
            self.stdout.write(f'Running scheduled scan: {scan.name}')
            self.execute_scheduled_scan(scan)
        except ScheduledScan.DoesNotExist:
            self.stderr.write(f'Scheduled scan with ID {scan_id} not found')

    def execute_scheduled_scan(self, scheduled_scan):
        """Execute a scheduled scan"""
        from aiScanner.models import ScheduledScanExecution, ScanHistory
        from aiScanner.aiScannerManager import AIScannerManager
        from loginSystem.models import Administrator
        from websiteFunctions.models import Websites
        from plogical.CyberCPLogFileWriter import CyberCPLogFileWriter as logging
        
        # Create execution record
        execution = ScheduledScanExecution.objects.create(
            scheduled_scan=scheduled_scan,
            status='running',
            started_at=timezone.now()
        )
        
        try:
            # Update last run time
            scheduled_scan.last_run = timezone.now()
            scheduled_scan.next_run = scheduled_scan.calculate_next_run()
            scheduled_scan.save()
            
            # Get domains to scan
            domains_to_scan = []
            admin = scheduled_scan.admin
            
            # Validate domains still exist and user has access
            for domain in scheduled_scan.domain_list:
                try:
                    website = Websites.objects.get(domain=domain, admin=admin)
                    domains_to_scan.append(domain)
                except Websites.DoesNotExist:
                    logging.writeToFile(f'[Scheduled Scan] Domain {domain} no longer accessible for user {admin.userName}')
                    continue
            
            if not domains_to_scan:
                execution.status = 'failed'
                execution.error_message = 'No accessible domains found for scanning'
                execution.completed_at = timezone.now()
                execution.save()
                self.stderr.write(f'No accessible domains for scheduled scan {scheduled_scan.name}')
                return
            
            execution.set_scanned_domains(domains_to_scan)
            execution.total_scans = len(domains_to_scan)
            execution.save()
            
            # Initialize scanner manager
            sm = AIScannerManager()
            scan_ids = []
            successful_scans = 0
            failed_scans = 0
            total_cost = 0.0
            
            # Execute scans for each domain
            for domain in domains_to_scan:
                try:
                    self.stdout.write(f'Starting scan for domain: {domain}')
                    
                    # Create a fake request object for the scanner manager
                    class FakeRequest:
                        def __init__(self, admin_id, domain, scan_type):
                            self.session = {'userID': admin_id}
                            self.method = 'POST'
                            self.POST = {
                                'domain': domain,
                                'scan_type': scan_type
                            }
                            # Create JSON body that startScan expects
                            import json
                            self.body = json.dumps({
                                'domain': domain,
                                'scan_type': scan_type
                            }).encode('utf-8')
                            
                        def get_host(self):
                            # Get the hostname from CyberPanel settings
                            try:
                                from plogical.acl import ACLManager
                                server_ip = ACLManager.fetchIP()
                                return f"{server_ip}:8090"  # Default CyberPanel port
                            except:
                                return "localhost:8090"  # Fallback
                    
                    fake_request = FakeRequest(admin.pk, domain, scheduled_scan.scan_type)
                    
                    # Start the scan
                    result = sm.startScan(fake_request, admin.pk)
                    
                    if hasattr(result, 'content'):
                        # It's an HTTP response, parse the JSON
                        import json
                        response_data = json.loads(result.content.decode('utf-8'))
                    else:
                        # It's already a dict
                        response_data = result
                    
                    if response_data.get('success'):
                        scan_id = response_data.get('scan_id')
                        if scan_id:
                            scan_ids.append(scan_id)
                            successful_scans += 1
                            
                            # Get cost estimate if available
                            if 'cost_estimate' in response_data:
                                total_cost += float(response_data['cost_estimate'])
                            
                            logging.writeToFile(f'[Scheduled Scan] Successfully started scan {scan_id} for {domain}')
                        else:
                            failed_scans += 1
                            logging.writeToFile(f'[Scheduled Scan] Failed to get scan ID for {domain}')
                    else:
                        failed_scans += 1
                        error_msg = response_data.get('error', 'Unknown error')
                        logging.writeToFile(f'[Scheduled Scan] Failed to start scan for {domain}: {error_msg}')
                
                except Exception as e:
                    failed_scans += 1
                    error_msg = str(e)
                    logging.writeToFile(f'[Scheduled Scan] Exception starting scan for {domain}: {error_msg}')
                    
                # Small delay between scans to avoid overwhelming the system
                time.sleep(2)
            
            # Update execution record
            execution.successful_scans = successful_scans
            execution.failed_scans = failed_scans
            execution.total_cost = total_cost
            execution.set_scan_ids(scan_ids)
            execution.status = 'completed' if failed_scans == 0 else 'completed'  # Always completed if we tried all
            execution.completed_at = timezone.now()
            execution.save()
            
            # Send notifications if configured
            if scheduled_scan.email_notifications:
                self.send_notifications(scheduled_scan, execution)
            
            self.stdout.write(
                f'Scheduled scan completed: {successful_scans} successful, {failed_scans} failed'
            )
            
        except Exception as e:
            # Update execution record with error
            execution.status = 'failed'
            execution.error_message = str(e)
            execution.completed_at = timezone.now()
            execution.save()
            
            logging.writeToFile(f'[Scheduled Scan] Failed to execute scheduled scan {scheduled_scan.name}: {str(e)}')
            self.stderr.write(f'Failed to execute scheduled scan {scheduled_scan.name}: {str(e)}')
            
            # Send failure notification
            if scheduled_scan.email_notifications and scheduled_scan.notify_on_failure:
                self.send_failure_notification(scheduled_scan, str(e))

    def send_notifications(self, scheduled_scan, execution):
        """Send email notifications for completed scan"""
        try:
            # Determine if we should send notification
            should_notify = False
            
            if execution.status == 'failed' and scheduled_scan.notify_on_failure:
                should_notify = True
            elif execution.status == 'completed':
                if scheduled_scan.notify_on_completion:
                    should_notify = True
                elif scheduled_scan.notify_on_threats and execution.successful_scans > 0:
                    # Check if any scans found threats
                    # This would require checking the scan results, which might not be available immediately
                    # For now, we'll just send completion notifications
                    should_notify = scheduled_scan.notify_on_completion
            
            if should_notify:
                self.send_execution_notification(scheduled_scan, execution)
                
        except Exception as e:
            from plogical.CyberCPLogFileWriter import CyberCPLogFileWriter as logging
            logging.writeToFile(f'[Scheduled Scan] Failed to send notification: {str(e)}')

    def send_execution_notification(self, scheduled_scan, execution):
        """Send notification email for scan execution"""
        try:
            # Get notification emails
            notification_emails = scheduled_scan.notification_email_list
            if not notification_emails:
                # Use admin email as fallback
                notification_emails = [scheduled_scan.admin.email] if scheduled_scan.admin.email else []
            
            if not notification_emails:
                return
            
            # Prepare email content
            subject = f'AI Scanner: Scheduled Scan "{scheduled_scan.name}" Completed'
            
            status_text = execution.status.title()
            if execution.status == 'completed':
                if execution.failed_scans == 0:
                    status_text = 'Completed Successfully'
                else:
                    status_text = f'Completed with {execution.failed_scans} failures'
            
            message = f"""
Scheduled AI Security Scan Report

Scan Name: {scheduled_scan.name}
Status: {status_text}
Execution Time: {execution.execution_time.strftime('%Y-%m-%d %H:%M:%S UTC')}

Results:
- Total Domains: {execution.total_scans}
- Successful Scans: {execution.successful_scans}
- Failed Scans: {execution.failed_scans}
- Total Cost: ${execution.total_cost:.4f}

Domains Scanned: {', '.join(execution.scanned_domains)}

{f'Error Message: {execution.error_message}' if execution.error_message else ''}

Scan IDs: {', '.join(execution.scan_id_list)}

View detailed results in your IndiansCloud AI Scanner dashboard.
"""
            
            # Send email using CyberPanel's email system
            from plogical.mailUtilities import mailUtilities
            sender = 'noreply@cyberpanel.local'
            mailUtilities.SendEmail(sender, notification_emails, message)
            
            # Log notification sent
            from plogical.CyberCPLogFileWriter import CyberCPLogFileWriter as logging
            logging.writeToFile(f'[Scheduled Scan] Notification sent for {scheduled_scan.name} to {len(notification_emails)} recipients')
            
        except Exception as e:
            from plogical.CyberCPLogFileWriter import CyberCPLogFileWriter as logging
            logging.writeToFile(f'[Scheduled Scan] Failed to send notification email: {str(e)}')

    def send_failure_notification(self, scheduled_scan, error_message):
        """Send notification email for scan failure"""
        try:
            # Get notification emails
            notification_emails = scheduled_scan.notification_email_list
            if not notification_emails:
                # Use admin email as fallback
                notification_emails = [scheduled_scan.admin.email] if scheduled_scan.admin.email else []
            
            if not notification_emails:
                return
            
            # Prepare email content
            subject = f'AI Scanner: Scheduled Scan "{scheduled_scan.name}" Failed'
            
            message = f"""
Scheduled AI Security Scan Failure

Scan Name: {scheduled_scan.name}
Status: Failed
Time: {timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC')}

Error: {error_message}

Please check your IndiansCloud AI Scanner configuration and try again.
"""
            
            # Send email using CyberPanel's email system
            from plogical.mailUtilities import mailUtilities
            sender = 'noreply@cyberpanel.local'
            mailUtilities.SendEmail(sender, notification_emails, message)
            
            # Log notification sent
            from plogical.CyberCPLogFileWriter import CyberCPLogFileWriter as logging
            logging.writeToFile(f'[Scheduled Scan] Failure notification sent for {scheduled_scan.name}')
            
        except Exception as e:
            from plogical.CyberCPLogFileWriter import CyberCPLogFileWriter as logging
            logging.writeToFile(f'[Scheduled Scan] Failed to send failure notification email: {str(e)}')