class GroupsQuerysetFilterMixin():

    def get_queryset(self):
        print("FILTERING BY GROUP :)")
        queryset = self.queryset
        queryset = queryset.filter(groups__in = self.request.user.groups.all())

        return queryset
