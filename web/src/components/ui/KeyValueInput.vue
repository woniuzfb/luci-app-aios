<script setup lang="ts">
import { computed } from 'vue';
import type { KeyValuePair } from '@/schema/types';

const props = withDefaults(
  defineProps<{
    modelValue?: KeyValuePair[];
    label?: string;
    keyPlaceholder?: string;
    valuePlaceholder?: string;
    addLabel?: string;
  }>(),
  {
    modelValue: () => [],
    keyPlaceholder: 'Header Name (如 Host)',
    valuePlaceholder: 'Value',
    addLabel: '+ 添加项'
  }
);

const emit = defineEmits<{
  (e: 'update:modelValue', value: KeyValuePair[]): void;
}>();

const list = computed(() => props.modelValue || []);

function addRow() {
  emit('update:modelValue', [{ key: '', value: '' }, ...list.value]);
}

function updateRow(idx: number, patch: Partial<KeyValuePair>) {
  const next = list.value.map((item, i) => (i === idx ? { ...item, ...patch } : item));
  emit('update:modelValue', next);
}

function removeRow(idx: number) {
  emit('update:modelValue', list.value.filter((_, i) => i !== idx));
}
</script>

<template>
  <div class="field">
    <div class="row-nowrap" style="justify-content: space-between">
      <label v-if="label">{{ label }}</label>
      <button type="button" class="btn btn-sm" @click="addRow">{{ addLabel }}</button>
    </div>
    <div v-if="list.length === 0" class="field-hint">暂无条目，点击右侧按钮连续添加。</div>
    <div v-else style="display: flex; flex-direction: column; gap: 6px">
      <div v-for="(pair, idx) in list" :key="idx" class="row-nowrap">
        <input
          type="text"
          :value="pair.key"
          :placeholder="keyPlaceholder"
          @input="updateRow(idx, { key: ($event.target as HTMLInputElement).value })"
        />
        <input
          type="text"
          :value="pair.value"
          :placeholder="valuePlaceholder"
          @input="updateRow(idx, { value: ($event.target as HTMLInputElement).value })"
        />
        <button type="button" class="btn btn-sm btn-danger" @click="removeRow(idx)">删</button>
      </div>
    </div>
  </div>
</template>
