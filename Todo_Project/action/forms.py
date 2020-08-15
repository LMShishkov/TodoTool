from django.forms import ModelForm
from .models import Action

class CreateActionForm(ModelForm):
    class Meta:
        model = Action
        fields = ['title', 'memo', 'important']