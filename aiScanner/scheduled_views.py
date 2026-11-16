from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from loginSystem.views import loadLoginPage
import json


@require_http_methods(['GET', 'POST'])
def scheduledScans(request):
    """Manage scheduled scans"""
    try:
        userID = request.session['userID']
        from loginSystem.models import Administrator
        from .models import ScheduledScan
        from plogical.acl import ACLManager
        
        admin = Administrator.objects.get(pk=userID)
        currentACL = ACLManager.loadedACL(userID)
        if currentACL.get('aiScannerAccess', 1) == 0:
            return JsonResponse({'success': False, 'error': 'Access denied'}, status=403)
        
        if request.method == 'GET':
            # Get scheduled scans with ACL respect
            if currentACL['admin'] == 1:
                # Admin can see all scheduled scans
                scheduled_scans = ScheduledScan.objects.all()
            else:
                # Users can only see their own scheduled scans and their sub-users' scans
                from .aiScannerManager import visible_admins
                user_admins = visible_admins(admin, False)
                scheduled_scans = ScheduledScan.objects.filter(admin__in=user_admins)
            
            scan_data = []
            for scan in scheduled_scans:
                scan_data.append({
                    'id': scan.id,
                    'name': scan.name,
                    'domains': scan.domain_list,
                    'frequency': scan.frequency,
                    'scan_type': scan.scan_type,
                    'time_of_day': scan.time_of_day.strftime('%H:%M'),
                    'day_of_week': scan.day_of_week,
                    'day_of_month': scan.day_of_month,
                    'status': scan.status,
                    'last_run': scan.last_run.isoformat() if scan.last_run else None,
                    'next_run': scan.next_run.isoformat() if scan.next_run else None,
                    'email_notifications': scan.email_notifications,
                    'notification_emails': scan.notification_email_list,
                    'notify_on_threats': scan.notify_on_threats,
                    'notify_on_completion': scan.notify_on_completion,
                    'notify_on_failure': scan.notify_on_failure,
                    'created_at': scan.created_at.isoformat()
                })
            
            return JsonResponse({'success': True, 'scheduled_scans': scan_data})
        
        elif request.method == 'POST':
            # Create new scheduled scan
            data = json.loads(request.body)
            
            # Validate required fields
            required_fields = ['name', 'domains', 'frequency', 'scan_type', 'time_of_day']
            for field in required_fields:
                if field not in data or not data[field]:
                    return JsonResponse({'success': False, 'error': f'Missing required field: {field}'})
            
            # Validate domains
            if not isinstance(data['domains'], list) or len(data['domains']) == 0:
                return JsonResponse({'success': False, 'error': 'At least one domain must be selected'})
            
            # Check if user has access to these domains
            if currentACL['admin'] != 1:
                from websiteFunctions.models import Websites
                user_domains = set(Websites.objects.filter(admin=admin).values_list('domain', flat=True))
                requested_domains = set(data['domains'])
                
                if not requested_domains.issubset(user_domains):
                    return JsonResponse({'success': False, 'error': 'You do not have access to some of the selected domains'})
            
            # Parse time
            from datetime import datetime
            try:
                time_obj = datetime.strptime(data['time_of_day'], '%H:%M').time()
            except ValueError:
                return JsonResponse({'success': False, 'error': 'Invalid time format'})
            
            # Create scheduled scan
            scheduled_scan = ScheduledScan(
                admin=admin,
                name=data['name'],
                frequency=data['frequency'],
                scan_type=data['scan_type'],
                time_of_day=time_obj,
                email_notifications=data.get('email_notifications', True),
                notify_on_threats=data.get('notify_on_threats', True),
                notify_on_completion=data.get('notify_on_completion', False),
                notify_on_failure=data.get('notify_on_failure', True)
            )
            
            # Set domains
            scheduled_scan.set_domains(data['domains'])
            
            # Set notification emails
            if data.get('notification_emails'):
                scheduled_scan.set_notification_emails(data['notification_emails'])
            
            # Set frequency-specific fields
            if data['frequency'] == 'weekly' and 'day_of_week' in data:
                scheduled_scan.day_of_week = int(data['day_of_week'])
            elif data['frequency'] in ['monthly', 'quarterly'] and 'day_of_month' in data:
                scheduled_scan.day_of_month = int(data['day_of_month'])
            if data['frequency'] == 'weekly' and scheduled_scan.day_of_week is None:
                scheduled_scan.day_of_week = 0
            if data['frequency'] in ['monthly', 'quarterly'] and scheduled_scan.day_of_month is None:
                scheduled_scan.day_of_month = 1
            if scheduled_scan.day_of_week is not None and not 0 <= scheduled_scan.day_of_week <= 6:
                return JsonResponse({'success': False, 'error': 'Invalid day of week'})
            if scheduled_scan.day_of_month is not None and not 1 <= scheduled_scan.day_of_month <= 31:
                return JsonResponse({'success': False, 'error': 'Invalid day of month'})
            
            scheduled_scan.save()
            
            return JsonResponse({'success': True, 'id': scheduled_scan.id})
            
    except KeyError:
        return JsonResponse({'success': False, 'error': 'Not authenticated'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})


@require_http_methods(['GET', 'DELETE'])
def scheduledScanDetail(request, scan_id):
    """Get or delete a specific scheduled scan"""
    try:
        userID = request.session['userID']
        from loginSystem.models import Administrator
        from .models import ScheduledScan
        from plogical.acl import ACLManager
        
        admin = Administrator.objects.get(pk=userID)
        currentACL = ACLManager.loadedACL(userID)
        if currentACL.get('aiScannerAccess', 1) == 0:
            return JsonResponse({'success': False, 'error': 'Access denied'}, status=403)
        
        # Get scheduled scan with ACL respect
        try:
            scheduled_scan = ScheduledScan.objects.get(id=scan_id)
            
            # Check if user has access to this scheduled scan
            if currentACL['admin'] != 1:
                from .aiScannerManager import visible_admins
                user_admins = visible_admins(admin, False)
                if scheduled_scan.admin not in user_admins:
                    return JsonResponse({'success': False, 'error': 'Access denied to this scheduled scan'})
        except ScheduledScan.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Scheduled scan not found'})
        
        if request.method == 'GET':
            # Return scheduled scan details
            scan_data = {
                'id': scheduled_scan.id,
                'name': scheduled_scan.name,
                'domains': scheduled_scan.domain_list,
                'frequency': scheduled_scan.frequency,
                'scan_type': scheduled_scan.scan_type,
                'time_of_day': scheduled_scan.time_of_day.strftime('%H:%M'),
                'day_of_week': scheduled_scan.day_of_week,
                'day_of_month': scheduled_scan.day_of_month,
                'status': scheduled_scan.status,
                'last_run': scheduled_scan.last_run.isoformat() if scheduled_scan.last_run else None,
                'next_run': scheduled_scan.next_run.isoformat() if scheduled_scan.next_run else None,
                'email_notifications': scheduled_scan.email_notifications,
                'notification_emails': scheduled_scan.notification_email_list,
                'notify_on_threats': scheduled_scan.notify_on_threats,
                'notify_on_completion': scheduled_scan.notify_on_completion,
                'notify_on_failure': scheduled_scan.notify_on_failure,
                'created_at': scheduled_scan.created_at.isoformat()
            }
            
            return JsonResponse({'success': True, 'scheduled_scan': scan_data})
        
        elif request.method == 'DELETE':
            # Delete scheduled scan
            scheduled_scan.delete()
            return JsonResponse({'success': True})
            
    except KeyError:
        return JsonResponse({'success': False, 'error': 'Not authenticated'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})


@require_http_methods(['POST'])
def toggleScheduledScan(request, scan_id):
    """Toggle scheduled scan status (active/paused)"""
    try:
        userID = request.session['userID']
        from loginSystem.models import Administrator
        from .models import ScheduledScan
        from plogical.acl import ACLManager
        
        admin = Administrator.objects.get(pk=userID)
        currentACL = ACLManager.loadedACL(userID)
        if currentACL.get('aiScannerAccess', 1) == 0:
            return JsonResponse({'success': False, 'error': 'Access denied'}, status=403)
        
        # Get scheduled scan with ACL respect
        try:
            scheduled_scan = ScheduledScan.objects.get(id=scan_id)
            
            # Check if user has access to this scheduled scan
            if currentACL['admin'] != 1:
                from .aiScannerManager import visible_admins
                user_admins = visible_admins(admin, False)
                if scheduled_scan.admin not in user_admins:
                    return JsonResponse({'success': False, 'error': 'Access denied to this scheduled scan'})
        except ScheduledScan.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Scheduled scan not found'})
        
        # Toggle status
        if scheduled_scan.status == 'active':
            scheduled_scan.status = 'paused'
        else:
            scheduled_scan.status = 'active'
        
        scheduled_scan.save()
        
        return JsonResponse({'success': True, 'status': scheduled_scan.status})
        
    except KeyError:
        return JsonResponse({'success': False, 'error': 'Not authenticated'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})


@require_http_methods(['GET'])
def scheduledScanExecutions(request, scan_id):
    """Get execution history for a scheduled scan"""
    try:
        userID = request.session['userID']
        from loginSystem.models import Administrator
        from .models import ScheduledScan, ScheduledScanExecution
        from plogical.acl import ACLManager
        
        admin = Administrator.objects.get(pk=userID)
        currentACL = ACLManager.loadedACL(userID)
        if currentACL.get('aiScannerAccess', 1) == 0:
            return JsonResponse({'success': False, 'error': 'Access denied'}, status=403)
        
        # Get scheduled scan with ACL respect
        try:
            scheduled_scan = ScheduledScan.objects.get(id=scan_id)
            
            # Check if user has access to this scheduled scan
            if currentACL['admin'] != 1:
                from .aiScannerManager import visible_admins
                user_admins = visible_admins(admin, False)
                if scheduled_scan.admin not in user_admins:
                    return JsonResponse({'success': False, 'error': 'Access denied to this scheduled scan'})
        except ScheduledScan.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Scheduled scan not found'})
        
        # Get execution history
        executions = ScheduledScanExecution.objects.filter(scheduled_scan=scheduled_scan).order_by('-execution_time')[:20]
        
        execution_data = []
        for execution in executions:
            execution_data.append({
                'id': execution.id,
                'execution_time': execution.execution_time.isoformat(),
                'status': execution.status,
                'domains_scanned': execution.scanned_domains,
                'total_scans': execution.total_scans,
                'successful_scans': execution.successful_scans,
                'failed_scans': execution.failed_scans,
                'total_cost': float(execution.total_cost),
                'scan_ids': execution.scan_id_list,
                'error_message': execution.error_message,
                'started_at': execution.started_at.isoformat() if execution.started_at else None,
                'completed_at': execution.completed_at.isoformat() if execution.completed_at else None
            })
        
        return JsonResponse({'success': True, 'executions': execution_data})
        
    except KeyError:
        return JsonResponse({'success': False, 'error': 'Not authenticated'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})