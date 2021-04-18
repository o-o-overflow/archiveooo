from django.contrib import admin
from .models import APICredential, UserSettings, VMSetup, Chal, ChalCheckout, VM, PublicFile, Tag, Hint, SpoileredNote, Achievement

@admin.register(APICredential)
class APICredentialAdmin(admin.ModelAdmin):
    list_display = ('id', 'owner_group',)
    search_fields = ('owner_group__name',)
    list_filter = ('owner_group__name',)


@admin.register(UserSettings)
class UserSettingsAdmin(admin.ModelAdmin):
    list_display = ('user', 'get_email', 'get_groups_string')
    search_fields = ('user__username', 'user__email')
    list_filter = ('user__groups', 'user__is_active', 'user__is_staff', 'user__is_superuser')
    save_on_top = True
    autocomplete_fields = ('user',)


@admin.register(VMSetup)
class VMSetupAdmin(admin.ModelAdmin):
    list_display = ('id', 'allow_player_docker', 'using_it', 'player_notice', 'machine_type', )
    search_fields = ('machine_type', 'replacement_user_script', 'extra_user_script', 'player_notice')


@admin.register(PublicFile)
class PublicFileAdmin(admin.ModelAdmin):
    list_display = ('id', 'filename', 'checkout', 'sha256', 'url')
    search_fields = ('filename', 'sha256', 'url')


class HintsInline(admin.TabularInline):
    model = Hint
    # TODO: CSS to remove the name: https://stackoverflow.com/questions/5086537/how-to-omit-object-name-from-djangos-tabularinline-admin-view
    # TODO: CSS to set the textbox width: 90%
class SpoileredNotesInline(admin.TabularInline):
    model = SpoileredNote

class PublicFilesInline(admin.TabularInline):
    model = PublicFile


#class CheckoutsInline(admin.TabularInline):
#    model = ChalCheckout
#    show_change_link = True
#    classes = ( 'collapse', )

#class VMSetupInline(admin.StackedInline):
#    model = VMSetup
#    show_change_link = True
#    classes = ( 'collapse', )


@admin.register(Chal)
class ChalAdmin(admin.ModelAdmin):
    list_display = ('format', 'name', 'is_public', 'public_checkout', 'has_checkouts', 'has_docker_img', 'has_source_url', 'owner_name', 'tags_str')
    list_display_links = ('name',)
    search_fields = ('format', 'name', 'owner_user__username', 'owner_group__name')
    list_filter = ('format', 'owner_user__username', 'owner_group__name')
    #ordering = ('format','name')
    fieldsets = (
        (None, {'fields': (('format', 'type', 'name'),
                           ('vm_setup', 'owner_user', 'owner_group'),
                           ('public_checkout',),
                           )}),
        ("Git pull config", {'fields': (('autopull_url','autopull_branch','autopull_submodules'),),}),
        ("Git pull deploy key", {'fields': ('autopull_deploy_key',), 'classes': ('collapse',)}),
        ("Game info", {'fields': (('points',),
                                  ('solves_n','solves_url'),
                                  ('pcaps_url', 'pcaps_notice'))}),
        ("Extra info", {'fields': (('source_url', 'source_notice'),
                                   ('extra_tags', 'yt_videoid', 'official_writeup_url', 'ctftime_url',),
                                   ('extra_description',),)}),
    )
    autocomplete_fields = ('owner_user', 'public_checkout', 'extra_tags',)
    # If too many: raw_id_fields = ('owner_user',)
    raw_id_fields = ('vm_setup',)
    inlines = ( HintsInline, SpoileredNotesInline, ) # TODO: VMSetupInline  CheckoutsInline
    save_on_top = True



@admin.register(ChalCheckout)
class ChalCheckoutAdmin(admin.ModelAdmin):
    date_hierarchy = 'creation_time'
    list_display = ('__str__', 'public', 'creation_time', 'chal', 'offline', 'docker_image_built', 'ran_test_deployed')
    list_editable = ('public',)
    list_filter = ('public', 'offline', 'docker_image_built', 'ran_test_deployed')
    search_fields = ('chal__name', 'commit_hash', 'creation_time', 'creation_info')
    raw_id_fields = ('vm_setup',)
    autocomplete_fields = ('tags','creation_user')
    save_on_top = True
    inlines = ( PublicFilesInline, ) # TODO: VMSetupInline
    fieldsets = (
        (None, {'fields': (('public',),)}),
        (None, {'fields': (('chal', 'offline', 'vm_setup'),)}),
        ("Checkout creation info", {'fields': (('docker_image_built', 'dockerhub_uri'),
                                  ('ran_tester', 'ran_test_deployed', 'tester_gave_errors', 'tester_gave_warnings'),
                                  ('creation_user', 'creation_time'),
                                  ('commit_hash', 'branch', 'dirty_tree'),
                                  ('pull_url', 'via_autopull'),)}),
        ("Extra creation info", {'fields': ('tester_output','creation_info'), 'classes': ('collapse',)}),
        ("Records from info.yml", {'fields': (('tags', 'exposed_port', 'default_flag', 'violates_flag_format'),
                           ('description', 'authors'),)}),
        ("Local-cache info", {'fields': (('cache','cache_until'),
                                         ('docker_image_tgzpath','docker_image_tgzurl','docker_image_tgzsha256'),),
                                         'classes': ('collapse',)})
    )
    readonly_fields = ('creation_time','via_autopull','ran_tester','ran_test_deployed')



@admin.register(VM)
class VMAdmin(admin.ModelAdmin):
    # TODO: warning that all fields are intended as read-only
    #date_hierarchy = 'creation_time'
    list_display = ('id', 'deleted', 'ip', 'creation_time','pingback_received', 'checkout')
    list_filter = ('deleted',)
    search_fields = ('ip', 'checkout__chal__name', 'checkout__commit_hash', 'creation_time')
    raw_id_fields = ('vm_setup',)
    autocomplete_fields = ('checkout','credentials','creation_user')
    list_display_links = ('id','ip')
    readonly_fields = ('pingback_uuid','creation_time')


@admin.register(Tag)
class TagAdmin(admin.ModelAdmin):
    list_display = ('name',) #, 'number_of_challenges_using_it')
    search_fields = ('name',)


@admin.register(Achievement)
class AchievementAdmin(admin.ModelAdmin):
    list_display = ('name', 'how')
    autocomplete_fields = ('tag',)
    search_fields = ('name', 'how', 'text', 'tags__name')
    fieldsets = (
        (None, {'fields': (('name','how','text'),)}),
        ("Auto-assign based on one of", {'fields': (('tag', 'points', ),)}),)
    #TODO: code
    #TODO: admin_actions recalc


@admin.register(Hint)
class HintAdmin(admin.ModelAdmin):
    list_display = ('id', 'chal', 'text')
    list_editable = ('text',)
    search_fields = ('chal__name', 'text')

@admin.register(SpoileredNote)
class SpoileredNoteAdmin(admin.ModelAdmin):
    list_display = ('id', 'chal', 'name', 'text')
    list_editable = ('name', 'text',)
    search_fields = ('chal__name', 'name', 'text')
