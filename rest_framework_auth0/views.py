class GroupsQuerysetFilterMixin():
    """
    Filter a queryset based on the groups asociated to the model instance
    we're requesting
    """

    def get_queryset(self):
        print("FILTERING BY GROUP :)")
        queryset = self.queryset
        queryset = queryset.filter(groups__in = self.request.user.groups.all())

        return queryset
