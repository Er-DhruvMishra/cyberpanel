<div class="panel card panel-default mb-3">
    <div class="panel-heading card-header"><h3 class="panel-title card-title m-0">IndiansCloud hosting</h3></div>
    <div class="panel-body card-body">
        <div class="row">
            <div class="col-sm-5 text-right"><strong>Domain</strong></div><div class="col-sm-7">{$domain|escape}</div>
            <div class="col-sm-5 text-right"><strong>Panel username</strong></div><div class="col-sm-7">{$username|escape}</div>
            <div class="col-sm-5 text-right"><strong>Panel address</strong></div><div class="col-sm-7">{$panelUrl|escape}</div>
            {if $usage}
            <div class="col-sm-5 text-right"><strong>Disk used</strong></div>
            <div class="col-sm-7">{$usage.total.disk_mb|escape} MB{if $usage.total.disk_limit_mb} of {$usage.total.disk_limit_mb|escape} MB{/if}</div>
            <div class="col-sm-5 text-right"><strong>Bandwidth used</strong></div>
            <div class="col-sm-7">{$usage.total.bandwidth_mb|escape} MB{if $usage.total.bandwidth_limit_mb} of {$usage.total.bandwidth_limit_mb|escape} MB{/if}</div>
            <div class="col-sm-5 text-right"><strong>Status</strong></div><div class="col-sm-7">{$usage.state|escape}</div>
            {/if}
        </div>
        {if $error}<p class="text-muted">{$error|escape}</p>{/if}
        <p class="text-center" style="margin-top:15px">
            <a href="clientarea.php?action=productdetails&amp;id={$serviceid}&amp;dosinglesignon=1" class="btn btn-primary" target="_blank">Log in to IndiansCloud</a>
        </p>
    </div>
</div>
