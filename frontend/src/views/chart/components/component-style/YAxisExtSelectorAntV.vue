<template>
  <div style="width: 100%">
    <el-col>
      <el-form ref="axisForm" :model="axisForm" label-width="80px" size="mini">
        <el-form-item v-show="showProperty('show')" :label="$t('chart.show')" class="form-item">
          <el-checkbox v-model="axisForm.show" @change="changeYAxisStyle('show')">{{ $t('chart.show') }}</el-checkbox>
        </el-form-item>
        <div v-show="axisForm.show">
          <el-form-item v-show="showProperty('position')" :label="$t('chart.position')" class="form-item">
            <el-radio-group v-model="axisForm.position" size="mini" @change="changeYAxisStyle('position')">
              <el-radio-button label="left">{{ $t('chart.text_pos_left') }}</el-radio-button>
              <el-radio-button label="right">{{ $t('chart.text_pos_right') }}</el-radio-button>
            </el-radio-group>
          </el-form-item>
          <el-form-item v-show="showProperty('name')" :label="$t('chart.name')" class="form-item">
            <el-input v-model="axisForm.name" size="mini" @blur="changeYAxisStyle('name')" />
          </el-form-item>
          <el-form-item v-show="showProperty('nameTextStyle')" :label="$t('chart.axis_name_color')" class="form-item">
            <el-color-picker v-model="axisForm.nameTextStyle.color" class="color-picker-style" :predefine="predefineColors" @change="changeYAxisStyle('nameTextStyle')" />
          </el-form-item>
          <el-form-item v-show="showProperty('nameTextStyle')" :label="$t('chart.axis_name_fontsize')" class="form-item">
            <el-select v-model="axisForm.nameTextStyle.fontSize" :placeholder="$t('chart.axis_name_fontsize')" @change="changeYAxisStyle('nameTextStyle')">
              <el-option v-for="option in fontSize" :key="option.value" :label="option.name" :value="option.value" />
            </el-select>
          </el-form-item>
          <span v-show="showProperty('axisValue')">
            <el-divider />
            <el-form-item class="form-item">
              <span slot="label">
                <span class="span-box">
                  <span>{{ $t('chart.axis_value') }}</span>
                  <el-tooltip class="item" effect="dark" placement="bottom">
                    <div slot="content">
                      最小值、最大值、间隔均为数值类型；若不填，则该项视为自动。
                      <br>
                      请确保填写数值能正确计算，否则将无法正常显示轴值。
                    </div>
                    <i class="el-icon-info" style="cursor: pointer;" />
                  </el-tooltip>
                </span>
              </span>
              <el-checkbox v-model="axisForm.axisValue.auto" @change="changeYAxisStyle('axisValue')">{{ $t('chart.axis_auto') }}</el-checkbox>
            </el-form-item>
            <span v-show="!axisForm.axisValue.auto">
              <el-form-item :label="$t('chart.axis_value_min')" class="form-item">
                <el-input v-model="axisForm.axisValue.min" @blur="changeYAxisStyle('axisValue')" />
              </el-form-item>
              <el-form-item :label="$t('chart.axis_value_max')" class="form-item">
                <el-input v-model="axisForm.axisValue.max" @blur="changeYAxisStyle('axisValue')" />
              </el-form-item>
              <el-form-item :label="$t('chart.axis_value_split_count')" class="form-item">
                <el-input v-model="axisForm.axisValue.splitCount" @blur="changeYAxisStyle('axisValue')" />
              </el-form-item>
            </span>
          </span>
          <el-divider v-if="showProperty('splitLine')" />
          <el-form-item v-show="showProperty('splitLine')" :label="$t('chart.axis_show')" class="form-item">
            <el-checkbox v-model="axisForm.splitLine.show" @change="changeYAxisStyle('splitLine')">{{ $t('chart.axis_show') }}</el-checkbox>
          </el-form-item>
          <span v-show="showProperty('splitLine') && axisForm.splitLine.show">
            <el-form-item :label="$t('chart.axis_color')" class="form-item">
              <el-color-picker v-model="axisForm.splitLine.lineStyle.color" class="el-color-picker" :predefine="predefineColors" @change="changeYAxisStyle('splitLine')" />
            </el-form-item>
            <el-form-item :label="$t('chart.axis_width')" class="form-item form-item-slider">
              <el-slider v-model="axisForm.splitLine.lineStyle.width" :min="1" :max="10" show-input :show-input-controls="false" input-size="mini" @change="changeYAxisStyle('lineStyle')" />
            </el-form-item>
          </span>
          <el-divider v-if="showProperty('axisLabel')" />
          <el-form-item v-show="showProperty('axisLabel')" :label="$t('chart.axis_label_show')" class="form-item">
            <el-checkbox v-model="axisForm.axisLabel.show" @change="changeYAxisStyle('axisLabel')">{{ $t('chart.axis_label_show') }}</el-checkbox>
          </el-form-item>
          <span v-show="showProperty('axisLabel') && axisForm.axisLabel.show">
            <el-form-item :label="$t('chart.axis_label_color')" class="form-item">
              <el-color-picker v-model="axisForm.axisLabel.color" class="el-color-picker" :predefine="predefineColors" @change="changeYAxisStyle('axisLabel')" />
            </el-form-item>
            <el-form-item :label="$t('chart.axis_label_rotate')" class="form-item form-item-slider">
              <el-slider v-model="axisForm.axisLabel.rotate" show-input :show-input-controls="false" :min="-90" :max="90" input-size="mini" @change="changeYAxisStyle('axisLabel')" />
            </el-form-item>
            <el-form-item :label="$t('chart.axis_label_fontsize')" class="form-item">
              <el-select v-model="axisForm.axisLabel.fontSize" :placeholder="$t('chart.axis_label_fontsize')" @change="changeYAxisStyle('axisLabel')">
                <el-option v-for="option in fontSize" :key="option.value" :label="option.name" :value="option.value" />
              </el-select>
            </el-form-item>
          </span>
        </div>
      </el-form>
    </el-col>
  </div>
</template>

<script>
import { COLOR_PANEL, DEFAULT_YAXIS_EXT_STYLE } from '../../chart/chart'

export default {
  name: 'YAxisExtSelectorAntV',
  props: {
    param: {
      type: Object,
      required: true
    },
    chart: {
      type: Object,
      required: true
    },
    propertyInner: {
      type: Array,
      required: false,
      default: function() {
        return []
      }
    }
  },
  data() {
    return {
      axisForm: JSON.parse(JSON.stringify(DEFAULT_YAXIS_EXT_STYLE)),
      isSetting: false,
      fontSize: [],
      predefineColors: COLOR_PANEL
    }
  },
  watch: {
    'chart': {
      handler: function() {
        this.initData()
      }
    }
  },
  mounted() {
    this.init()
    this.initData()
  },
  methods: {
    initData() {
      const chart = JSON.parse(JSON.stringify(this.chart))
      if (chart.customStyle) {
        // if (!chart.customStyle.yAxisExt) {
        //   chart.customStyle.yAxisExt = JSON.parse(JSON.stringify(DEFAULT_YAXIS_EXT_STYLE))
        // }
        let customStyle = null
        if (Object.prototype.toString.call(chart.customStyle) === '[object Object]') {
          customStyle = JSON.parse(JSON.stringify(chart.customStyle))
        } else {
          customStyle = JSON.parse(chart.customStyle)
        }
        if (customStyle.yAxisExt) {
          this.axisForm = customStyle.yAxisExt
          if (!this.axisForm.splitLine) {
            this.axisForm.splitLine = JSON.parse(JSON.stringify(DEFAULT_YAXIS_EXT_STYLE.splitLine))
          }
          if (!this.axisForm.nameTextStyle) {
            this.axisForm.nameTextStyle = JSON.parse(JSON.stringify(DEFAULT_YAXIS_EXT_STYLE.nameTextStyle))
          }
          if (!this.axisForm.axisValue) {
            this.axisForm.axisValue = JSON.parse(JSON.stringify(DEFAULT_YAXIS_EXT_STYLE.axisValue))
          }
        }
      }
    },
    init() {
      const arr = []
      for (let i = 6; i <= 40; i = i + 2) {
        arr.push({
          name: i + '',
          value: i + ''
        })
      }
      this.fontSize = arr
    },
    changeYAxisStyle(modifyName) {
      if (!this.axisForm.show) {
        this.isSetting = false
      }
      if (this.axisForm.axisValue.splitCount && (parseInt(this.axisForm.axisValue.splitCount) > 100 || parseInt(this.axisForm.axisValue.splitCount) < 0)) {
        this.$message({
          message: this.$t('chart.splitCount_less_100'),
          type: 'error'
        })
        return
      }
      this.axisForm['modifyName'] = modifyName
      this.$emit('onChangeYAxisForm', this.axisForm)
    },
    showProperty(property) {
      return this.propertyInner.includes(property)
    }
  }
}
</script>

<style scoped>
  .el-divider--horizontal {
    margin: 10px 0
  }
.shape-item{
  padding: 6px;
  border: none;
  width: 100%;
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.form-item-slider>>>.el-form-item__label{
  font-size: 12px;
  line-height: 38px;
}
.form-item>>>.el-form-item__label{
  font-size: 12px;
}
.el-select-dropdown__item{
  padding: 0 20px;
}
  span{
    font-size: 12px
  }
  .el-form-item{
    margin-bottom: 6px;
  }

.switch-style{
  position: absolute;
  right: 10px;
  margin-top: -4px;
}
  .color-picker-style{
    cursor: pointer;
    z-index: 1003;
  }
</style>
